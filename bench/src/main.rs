//! Benchmark for the tunnel: a destination server with configurable latency
//! and a load generator that holds a fixed number of concurrent HTTP/1.1
//! connections against the tunnel server, stepping up the count.
//!
//! ```text
//! load ──N TCP conns──► tunnel-server ══QUIC══► tunnel-client ──► destination
//! ```
//!
//! Every connection sends requests back to back for `--duration` seconds, so
//! the number of connections is also the number of requests in flight.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use axum::Router;
use axum::extract::Query;
use clap::{Parser, Subcommand};
use hdrhistogram::Histogram;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio::sync::Barrier;
use tokio::time::{Instant, sleep, timeout};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Serves `GET /?delay_ms=N&size=B`: waits N ms, then returns B bytes.
    Destination {
        #[arg(long, default_value = "0.0.0.0:3000")]
        listen: SocketAddr,
    },
    /// Steps through connection counts and reports throughput and latency.
    Load(LoadArgs),
}

#[derive(clap::Args, Debug, Clone)]
struct LoadArgs {
    /// Tunnel server HTTP address, `host:port`.
    #[arg(long)]
    target: String,

    /// Concurrent connection counts to test, in order.
    #[arg(long, value_delimiter = ',', default_value = "100,500,1000,2000,5000")]
    connections: Vec<usize>,

    /// Seconds each step sends requests for.
    #[arg(long, default_value_t = 20)]
    duration: u64,

    /// Destination delay per request, in ms. Keeps requests in flight.
    #[arg(long, default_value_t = 100)]
    delay_ms: u64,

    /// Response body size in bytes.
    #[arg(long, default_value_t = 128)]
    size: usize,

    /// Seconds before a single request counts as timed out.
    #[arg(long, default_value_t = 60)]
    timeout: u64,

    /// Seconds to pause between steps so connections drain.
    #[arg(long, default_value_t = 5)]
    pause: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        Command::Destination { listen } => destination(listen).await,
        Command::Load(args) => load(args).await,
    }
}

#[derive(Deserialize)]
struct DestParams {
    #[serde(default)]
    delay_ms: u64,
    #[serde(default)]
    size: usize,
}

async fn destination(listen: SocketAddr) -> Result<()> {
    let app = Router::new().fallback(|Query(p): Query<DestParams>| async move {
        sleep(Duration::from_millis(p.delay_ms)).await;
        vec![b'x'; p.size]
    });
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .context("binding destination")?;
    println!("destination listening on {listen}");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Per-connection results, merged after the step.
struct ConnStats {
    latency_us: Histogram<u64>,
    ok: u64,
    errors: BTreeMap<String, u64>,
}

impl ConnStats {
    fn new() -> Self {
        Self {
            // 2 significant digits keeps one histogram per connection small.
            latency_us: Histogram::new_with_bounds(1, 600_000_000, 2).expect("valid bounds"),
            ok: 0,
            errors: BTreeMap::new(),
        }
    }

    fn error(&mut self, kind: impl Into<String>) {
        *self.errors.entry(kind.into()).or_default() += 1;
    }
}

async fn load(args: LoadArgs) -> Result<()> {
    let addr = tokio::net::lookup_host(&args.target)
        .await
        .with_context(|| format!("resolving {}", args.target))?
        .next()
        .with_context(|| format!("no address for {}", args.target))?;
    let path = format!("/?delay_ms={}&size={}", args.delay_ms, args.size);

    println!(
        "target={} delay={}ms size={}B duration={}s",
        args.target, args.delay_ms, args.size, args.duration
    );
    println!(
        "{:>7} {:>7} {:>10} {:>9} {:>9} {:>8} {:>8} {:>8} {:>8} {:>8}  errors",
        "conns", "open", "requests", "rps", "ideal", "eff%", "p50ms", "p90ms", "p99ms", "maxms"
    );
    for (i, &n) in args.connections.iter().enumerate() {
        if i > 0 {
            sleep(Duration::from_secs(args.pause)).await;
        }
        step(&args, addr, &path, n).await?;
    }
    Ok(())
}

async fn step(args: &LoadArgs, addr: SocketAddr, path: &str, n: usize) -> Result<()> {
    if n == 0 {
        bail!("connection count must be positive");
    }
    // All connections open first, then start sending together.
    let barrier = Arc::new(Barrier::new(n + 1));
    let duration = Duration::from_secs(args.duration);
    let req_timeout = Duration::from_secs(args.timeout);
    let mut tasks = Vec::with_capacity(n);
    for _ in 0..n {
        let barrier = barrier.clone();
        let host = args.target.clone();
        let path = path.to_owned();
        tasks.push(tokio::spawn(async move {
            connection(addr, host, path, barrier, duration, req_timeout).await
        }));
    }
    barrier.wait().await;
    let started = Instant::now();

    let mut total = ConnStats::new();
    let mut open = 0usize;
    for task in tasks {
        let (connected, stats) = task.await?;
        open += usize::from(connected);
        total.latency_us.add(&stats.latency_us)?;
        total.ok += stats.ok;
        for (kind, count) in stats.errors {
            *total.errors.entry(kind).or_default() += count;
        }
    }
    let elapsed = started.elapsed().as_secs_f64();

    let rps = total.ok as f64 / elapsed;
    // Throughput if every connection only waited for the destination delay.
    let ideal = if args.delay_ms > 0 {
        n as f64 * 1000.0 / args.delay_ms as f64
    } else {
        f64::NAN
    };
    let ms = |q: f64| total.latency_us.value_at_quantile(q) as f64 / 1000.0;
    let errors = if total.errors.is_empty() {
        "-".to_owned()
    } else {
        total
            .errors
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    println!(
        "{:>7} {:>7} {:>10} {:>9.0} {:>9.0} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>8.1}  {}",
        n,
        open,
        total.ok,
        rps,
        ideal,
        rps / ideal * 100.0,
        ms(0.5),
        ms(0.9),
        ms(0.99),
        total.latency_us.max() as f64 / 1000.0,
        errors
    );
    Ok(())
}

/// One HTTP/1.1 keep-alive connection sending requests until `duration` has
/// passed since the barrier. Returns whether it connected, and its stats.
async fn connection(
    addr: SocketAddr,
    host: String,
    path: String,
    barrier: Arc<Barrier>,
    duration: Duration,
    req_timeout: Duration,
) -> (bool, ConnStats) {
    let mut stats = ConnStats::new();
    let sender = match open(addr).await {
        Ok(sender) => Some(sender),
        Err(e) => {
            stats.error(format!("connect:{}", e.kind()));
            None
        }
    };
    barrier.wait().await;
    let Some(mut sender) = sender else {
        return (false, stats);
    };

    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        let req = hyper::Request::get(path.as_str())
            .header(hyper::header::HOST, host.as_str())
            .body(Empty::<Bytes>::new())
            .expect("valid request");
        let start = Instant::now();
        let result = timeout(req_timeout, async {
            sender.ready().await?;
            let resp = sender.send_request(req).await?;
            let status = resp.status();
            resp.into_body().collect().await?;
            Ok::<_, hyper::Error>(status)
        })
        .await;
        match result {
            Ok(Ok(status)) if status.is_success() => {
                stats.ok += 1;
                stats
                    .latency_us
                    .saturating_record(start.elapsed().as_micros() as u64);
            }
            Ok(Ok(status)) => stats.error(format!("http{}", status.as_u16())),
            Ok(Err(_)) => {
                stats.error("io");
                // The connection is unusable after an error; reopen it.
                match open(addr).await {
                    Ok(s) => sender = s,
                    Err(e) => {
                        stats.error(format!("connect:{}", e.kind()));
                        break;
                    }
                }
            }
            Err(_) => {
                stats.error("timeout");
                break;
            }
        }
    }
    (true, stats)
}

async fn open(addr: SocketAddr) -> std::io::Result<http1::SendRequest<Empty<Bytes>>> {
    let stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true)?;
    let (sender, conn) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(std::io::Error::other)?;
    tokio::spawn(conn);
    Ok(sender)
}
