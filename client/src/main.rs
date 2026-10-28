//! Tunnel client: keeps a QUIC connection to the tunnel server (trusting only
//! the pinned server public key) and forwards every tunneled request to the
//! configured destination.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use futures_util::StreamExt;
use quinn::crypto::rustls::QuicClientConfig;
use reqwest::Url;
use tokio::time::sleep;
use tracing::{debug, info, warn};
use tunnel_common::protocol::{
    RequestHead, ResponseHead, headers_from_wire, headers_to_wire, read_frame, write_frame,
};
use tunnel_common::tls::{Fingerprint, parse_fingerprint, pinned_client_config};

const MIN_BACKOFF: Duration = Duration::from_millis(500);
const MAX_BACKOFF: Duration = Duration::from_secs(10);
/// Stream reset code sent when the destination response fails midway.
const UPSTREAM_ERROR: u32 = 1;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Tunnel server QUIC address, `host:port`.
    #[arg(long, env = "TUNNEL_SERVER")]
    server: String,

    /// SHA-256 fingerprint (hex) of the server public key; the only key trusted.
    #[arg(long, env = "TUNNEL_SERVER_PIN", value_parser = parse_fingerprint)]
    server_pin: Fingerprint,

    /// Base URL requests are forwarded to, e.g. `http://127.0.0.1:3000`.
    #[arg(long, env = "TUNNEL_DESTINATION")]
    destination: Url,

    /// Seconds to wait for the destination to respond.
    #[arg(long, env = "TUNNEL_DESTINATION_TIMEOUT", default_value_t = 30)]
    destination_timeout: u64,

    /// Seconds without traffic before the tunnel is considered dead and
    /// reconnected. Keepalives are sent at a third of this interval.
    #[arg(long, env = "TUNNEL_IDLE_TIMEOUT", default_value_t = 10,
          value_parser = clap::value_parser!(u64).range(1..))]
    idle_timeout: u64,

    /// Maximum request body size in bytes accepted from the server.
    #[arg(long, env = "TUNNEL_MAX_BODY", default_value_t = 16 * 1024 * 1024)]
    max_body: usize,

    /// Maximum number of concurrently tunneled requests.
    #[arg(long, env = "TUNNEL_MAX_CONCURRENT", default_value_t = 1024)]
    max_concurrent: u32,
}

struct Forwarder {
    http: reqwest::Client,
    destination: Url,
    max_body: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // reqwest is built without a bundled provider; use ring like the tunnel.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("no other crypto provider installed");

    let args = Args::parse();
    if !matches!(args.destination.scheme(), "http" | "https") {
        bail!("destination must be an http or https URL");
    }

    let forwarder = Arc::new(Forwarder {
        http: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(args.destination_timeout))
            .build()?,
        destination: args.destination,
        max_body: args.max_body,
    });
    let quic_config = quic_client_config(
        args.server_pin,
        args.max_concurrent,
        Duration::from_secs(args.idle_timeout),
    )?;

    let mut backoff = MIN_BACKOFF;
    loop {
        match connect(&args.server, quic_config.clone()).await {
            Ok(conn) => {
                info!(server = %args.server, "tunnel connected");
                backoff = MIN_BACKOFF;
                let reason = serve(conn, forwarder.clone()).await;
                warn!("tunnel connection lost: {reason}");
            }
            Err(e) => warn!(server = %args.server, "connect failed: {e:#}"),
        }
        info!("reconnecting in {backoff:?}");
        sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

fn quic_client_config(
    pin: Fingerprint,
    max_concurrent: u32,
    idle_timeout: Duration,
) -> Result<quinn::ClientConfig> {
    let tls = pinned_client_config(pin)?;
    let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    let mut transport = quinn::TransportConfig::default();
    // Bidi streams are opened by the server, one per request.
    transport.max_concurrent_bidi_streams(max_concurrent.into());
    transport.max_concurrent_uni_streams(0u32.into());
    // Keepalives detect a dead path quickly and keep NAT mappings open.
    // The effective idle timeout is the lower of ours and the server's.
    transport.keep_alive_interval(Some(idle_timeout / 3));
    transport.max_idle_timeout(Some(idle_timeout.try_into()?));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

async fn connect(server: &str, config: quinn::ClientConfig) -> Result<quinn::Connection> {
    let addr = tokio::net::lookup_host(server)
        .await
        .with_context(|| format!("resolving {server}"))?
        .next()
        .with_context(|| format!("no address for {server}"))?;
    let bind: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse()?
    } else {
        "0.0.0.0:0".parse()?
    };
    let mut endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(config);
    // Identity comes from the pinned key, so the SNI name is informational.
    let conn = endpoint.connect(addr, "quic-http-tunnel")?.await?;
    Ok(conn)
}

/// Handles streams until the connection closes, returning the reason.
async fn serve(conn: quinn::Connection, forwarder: Arc<Forwarder>) -> quinn::ConnectionError {
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let forwarder = forwarder.clone();
                tokio::spawn(async move {
                    if let Err(e) = forwarder.handle(send, recv).await {
                        warn!("request failed: {e:#}");
                    }
                });
            }
            Err(e) => return e,
        }
    }
}

impl Forwarder {
    async fn handle(&self, mut send: quinn::SendStream, mut recv: quinn::RecvStream) -> Result<()> {
        let head: RequestHead = read_frame(&mut recv)
            .await
            .context("reading request head")?;
        let body = recv
            .read_to_end(self.max_body)
            .await
            .context("reading request body")?;
        if body.len() as u64 != head.body_len {
            // The server gave up mid-send; don't forward a truncated request.
            bail!(
                "truncated body: got {} of {} bytes",
                body.len(),
                head.body_len
            );
        }
        debug!(method = %head.method, uri = %head.uri, "forwarding");

        let response = match self.send_upstream(&head, body).await {
            Ok(response) => response,
            Err(e) => {
                warn!(method = %head.method, uri = %head.uri, "destination error: {e:#}");
                let head = ResponseHead {
                    status: 502,
                    headers: vec![("content-type".into(), b"text/plain".to_vec())],
                };
                write_frame(&mut send, &head).await?;
                send.write_all(format!("destination error: {e:#}\n").as_bytes())
                    .await?;
                send.finish()?;
                return Ok(());
            }
        };

        let head = ResponseHead {
            status: response.status().as_u16(),
            headers: headers_to_wire(response.headers(), &[]),
        };
        write_frame(&mut send, &head).await?;

        let mut body = response.bytes_stream();
        while let Some(chunk) = body.next().await {
            match chunk {
                Ok(chunk) => send.write_all(&chunk).await?,
                Err(e) => {
                    // Reset instead of finishing so the truncation is visible.
                    let _ = send.reset(UPSTREAM_ERROR.into());
                    bail!("destination body error: {e}");
                }
            }
        }
        send.finish()?;
        Ok(())
    }

    async fn send_upstream(&self, head: &RequestHead, body: Vec<u8>) -> Result<reqwest::Response> {
        let url = self.url_for(&head.uri)?;
        let method = reqwest::Method::from_bytes(head.method.as_bytes())?;
        let mut headers = headers_from_wire(&head.headers);
        // The destination gets its own Host; the original is in X-Forwarded-Host.
        headers.remove(reqwest::header::HOST);
        let response = self
            .http
            .request(method, url)
            .headers(headers)
            .body(body)
            .send()
            .await?;
        Ok(response)
    }

    /// Appends the request path and query to the destination base URL.
    fn url_for(&self, path_and_query: &str) -> Result<Url> {
        let base = self.destination.as_str().trim_end_matches('/');
        let path = if path_and_query.starts_with('/') {
            path_and_query
        } else {
            bail!("invalid request target {path_and_query:?}");
        };
        Ok(Url::parse(&format!("{base}{path}"))?)
    }
}
