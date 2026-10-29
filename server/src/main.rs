//! Tunnel server: accepts public HTTP requests and forwards them over QUIC to
//! the connected tunnel client. Only clients whose public key is pinned with
//! `--client-pin` can complete the QUIC handshake.
//!
//! A client may open several connections in one session (see
//! `tunnel_common::session`); each request goes to the least loaded one.
//!
//! Requests are buffered in full so they can be replayed. While no client is
//! connected, or when the connection drops before a response head arrives, the
//! request waits and is retried on the next connection, until
//! `--request-timeout` expires (then the caller gets a 504).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use clap::Parser;
use futures_util::StreamExt;
use quinn::crypto::rustls::{HandshakeData, QuicServerConfig};
use rustls::pki_types::CertificateDer;
use tokio::sync::watch;
use tokio::time::{Instant, sleep, timeout_at};
use tokio_util::io::ReaderStream;
use tracing::{debug, info, warn};
use tunnel_common::identity::{self, Identity};
use tunnel_common::protocol::{
    RequestHead, ResponseHead, headers_from_wire, headers_to_wire, read_frame, write_frame,
};
use tunnel_common::session::{self, CountGuard, Role, SessionId};
use tunnel_common::tls::{
    Fingerprint, format_fingerprint, parse_fingerprint, pinned_server_config, spki_fingerprint,
};

/// Pause between attempts on the same connection, avoids a hot retry loop.
const RETRY_DELAY: Duration = Duration::from_millis(200);

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Address for incoming public HTTP traffic.
    #[arg(long, env = "TUNNEL_HTTP_LISTEN", default_value = "0.0.0.0:8080")]
    http_listen: SocketAddr,

    /// UDP address the tunnel client connects to.
    #[arg(long, env = "TUNNEL_QUIC_LISTEN", default_value = "0.0.0.0:4433")]
    quic_listen: SocketAddr,

    /// PEM certificate; generated together with the key if both are missing.
    #[arg(long, env = "TUNNEL_CERT", default_value = "server.crt")]
    cert: PathBuf,

    /// PEM private key; generated together with the certificate if both are missing.
    #[arg(long, env = "TUNNEL_KEY", default_value = "server.key")]
    key: PathBuf,

    /// SHA-256 fingerprint (hex) of a client public key allowed to connect.
    /// Repeat the flag, or separate with commas, to allow several keys.
    #[arg(long, env = "TUNNEL_CLIENT_PIN", value_parser = parse_fingerprint,
          value_delimiter = ',', required_unless_present = "print_fingerprint")]
    client_pin: Vec<Fingerprint>,

    /// Seconds a request may wait (queued and retried) for a response head.
    #[arg(long, env = "TUNNEL_REQUEST_TIMEOUT", default_value_t = 30)]
    request_timeout: u64,

    /// Maximum request body size in bytes (requests are buffered for retry).
    #[arg(long, env = "TUNNEL_MAX_BODY", default_value_t = 16 * 1024 * 1024)]
    max_body: usize,

    /// Print the public key fingerprint (generating a key if needed) and exit.
    #[arg(long)]
    print_fingerprint: bool,
}

#[derive(Clone)]
struct AppState {
    /// Connections of the current session, empty while no client is connected.
    pool: watch::Receiver<Pool>,
    request_timeout: Duration,
    max_body: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let identity = identity::load_or_generate(&args.cert, &args.key, "quic-http-tunnel")?;
    if args.print_fingerprint {
        println!("{}", identity.fingerprint);
        return Ok(());
    }
    info!(fingerprint = %identity.fingerprint, "server public key (pass to client as --server-pin)");

    info!(count = args.client_pin.len(), "client keys allowed");

    let endpoint = quinn::Endpoint::server(
        quic_server_config(identity, args.client_pin)?,
        args.quic_listen,
    )
    .context("binding QUIC endpoint")?;
    info!(addr = %args.quic_listen, "QUIC listening");

    let (pool_tx, pool_rx) = watch::channel(Pool::default());
    tokio::spawn(accept_tunnels(endpoint, pool_tx));

    let state = AppState {
        pool: pool_rx,
        request_timeout: Duration::from_secs(args.request_timeout),
        max_body: args.max_body,
    };
    let app = Router::new().fallback(proxy).with_state(state);
    let listener = tokio::net::TcpListener::bind(args.http_listen)
        .await
        .context("binding HTTP listener")?;
    info!(addr = %args.http_listen, "HTTP listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn quic_server_config(
    identity: Identity,
    client_pins: Vec<Fingerprint>,
) -> Result<quinn::ServerConfig> {
    let tls = pinned_server_config(identity, client_pins)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    let transport = Arc::get_mut(&mut config.transport).expect("fresh transport config");
    // Only the server opens streams.
    transport.max_concurrent_bidi_streams(0u32.into());
    transport.max_concurrent_uni_streams(0u32.into());
    transport.max_idle_timeout(Some(Duration::from_secs(15).try_into()?));
    Ok(config)
}

/// A tunnel connection and the number of requests using it.
#[derive(Clone)]
struct Tunnel {
    conn: quinn::Connection,
    in_flight: Arc<AtomicUsize>,
}

#[derive(Default)]
struct Pool {
    /// `None` for an older client without sessions, which nothing can join.
    session: Option<SessionId>,
    tunnels: Vec<Tunnel>,
}

impl Pool {
    fn least_loaded(&self) -> Option<Tunnel> {
        self.tunnels
            .iter()
            .min_by_key(|t| t.in_flight.load(Ordering::Relaxed))
            .cloned()
    }
}

/// Accepts tunnel clients. Unpinned clients fail the handshake; among pinned
/// ones, a connection starting a session replaces all previous connections,
/// and one joining the current session is added to it.
async fn accept_tunnels(endpoint: quinn::Endpoint, pool_tx: watch::Sender<Pool>) {
    let pool_tx = Arc::new(pool_tx);
    while let Some(incoming) = endpoint.accept().await {
        let pool_tx = pool_tx.clone();
        tokio::spawn(async move {
            let remote = incoming.remote_address();
            let conn = match incoming.await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!(%remote, "tunnel handshake failed: {e}");
                    return;
                }
            };
            let client = client_fingerprint(&conn).unwrap_or_else(|| "unknown".to_owned());
            let hello = server_name(&conn).and_then(|name| session::parse_server_name(&name));
            let tunnel = Tunnel {
                conn: conn.clone(),
                in_flight: Arc::default(),
            };
            let mut connections = 0;
            let accepted = pool_tx.send_if_modified(|pool| {
                match hello {
                    Some((id, Role::Join)) if pool.session != Some(id) => return false,
                    Some((_, Role::Join)) => {}
                    _ => {
                        for old in pool.tunnels.drain(..) {
                            old.conn.close(0u32.into(), b"replaced by newer connection");
                        }
                        pool.session = hello.map(|(id, _)| id);
                    }
                }
                pool.tunnels.push(tunnel);
                connections = pool.tunnels.len();
                true
            });
            let session = hello.map_or_else(|| "none".to_owned(), |(id, _)| id.to_string());
            if !accepted {
                warn!(%remote, %client, %session, "rejecting join to unknown session");
                conn.close(session::UNKNOWN_SESSION.into(), b"unknown session");
                return;
            }
            info!(%remote, id = conn.stable_id(), %client, %session, connections, "tunnel client connected");

            let reason = conn.closed().await;
            info!(%remote, id = conn.stable_id(), "tunnel client disconnected: {reason}");
            pool_tx.send_if_modified(|pool| {
                let before = pool.tunnels.len();
                pool.tunnels
                    .retain(|t| t.conn.stable_id() != conn.stable_id());
                pool.tunnels.len() != before
            });
        });
    }
}

/// The TLS server name (SNI) the client sent, which carries its session.
fn server_name(conn: &quinn::Connection) -> Option<String> {
    conn.handshake_data()?
        .downcast::<HandshakeData>()
        .ok()?
        .server_name
}

/// Hex fingerprint of the key the client authenticated with.
fn client_fingerprint(conn: &quinn::Connection) -> Option<String> {
    let certs = conn
        .peer_identity()?
        .downcast::<Vec<CertificateDer<'static>>>()
        .ok()?;
    let fp = spki_fingerprint(certs.first()?).ok()?;
    Some(format_fingerprint(&fp))
}

async fn proxy(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let deadline = Instant::now() + state.request_timeout;
    let (parts, body) = req.into_parts();

    let body = match axum::body::to_bytes(body, state.max_body).await {
        Ok(body) => body,
        Err(e) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("reading body: {e}\n"),
            )
                .into_response();
        }
    };

    let mut headers = parts.headers;
    if let Some(host) = headers.get(axum::http::header::HOST).cloned() {
        headers.insert("x-forwarded-host", host);
    }
    if let Ok(ip) = HeaderValue::from_str(&peer.ip().to_string()) {
        headers.append("x-forwarded-for", ip);
    }
    headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));

    let head = RequestHead {
        method: parts.method.to_string(),
        uri: parts
            .uri
            .path_and_query()
            .map_or_else(|| "/".to_owned(), |pq| pq.to_string()),
        headers: headers_to_wire(&headers, &[]),
        body_len: body.len() as u64,
    };

    match timeout_at(deadline, forward(&state, &head, &body)).await {
        Ok((resp_head, recv, in_flight)) => build_response(resp_head, recv, in_flight),
        Err(_) => {
            warn!(method = %head.method, uri = %head.uri, "request timed out waiting for tunnel");
            (StatusCode::GATEWAY_TIMEOUT, "tunnel timeout\n").into_response()
        }
    }
}

/// Sends the request over the tunnel, retrying on fresh connections until a
/// response head is received. Bounded by the caller's timeout.
async fn forward(
    state: &AppState,
    head: &RequestHead,
    body: &Bytes,
) -> (ResponseHead, quinn::RecvStream, CountGuard) {
    let mut pool_rx = state.pool.clone();
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        // Bind first so the non-Send watch guard is dropped before any await.
        let tunnel = pool_rx
            .wait_for(|pool| !pool.tunnels.is_empty())
            .await
            .map(|pool| pool.least_loaded());
        let Ok(Some(tunnel)) = tunnel else {
            // Sender lives as long as the accept loop; nothing to wait for.
            return std::future::pending().await;
        };

        match try_forward(&tunnel, head, body).await {
            Ok(result) => return result,
            Err(e) => {
                warn!(attempt, method = %head.method, uri = %head.uri, "tunnel attempt failed, retrying: {e:#}");
                sleep(RETRY_DELAY).await;
            }
        }
    }
}

/// Returns the response head and body stream, plus a guard that counts the
/// request against its connection until the body is done.
async fn try_forward(
    tunnel: &Tunnel,
    head: &RequestHead,
    body: &Bytes,
) -> Result<(ResponseHead, quinn::RecvStream, CountGuard)> {
    // Count before opening, so requests waiting for a stream also add load.
    let in_flight = CountGuard::new(&tunnel.in_flight);
    let (mut send, mut recv) = tunnel.conn.open_bi().await.context("opening stream")?;
    write_frame(&mut send, head)
        .await
        .context("sending request head")?;
    send.write_all(body).await.context("sending request body")?;
    send.finish()?;
    let resp_head: ResponseHead = read_frame(&mut recv)
        .await
        .context("reading response head")?;
    debug!(status = resp_head.status, uri = %head.uri, "response head received");
    Ok((resp_head, recv, in_flight))
}

fn build_response(head: ResponseHead, recv: quinn::RecvStream, in_flight: CountGuard) -> Response {
    let Ok(status) = StatusCode::from_u16(head.status) else {
        return (StatusCode::BAD_GATEWAY, "invalid upstream status\n").into_response();
    };
    // The stream owns the guard, so the request counts until the body ends.
    let body = ReaderStream::new(recv).map(move |chunk| {
        let _ = &in_flight;
        chunk
    });
    let mut response = Response::new(Body::from_stream(body));
    *response.status_mut() = status;
    *response.headers_mut() = headers_from_wire(&head.headers);
    response
}
