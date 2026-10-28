//! Tunnel server: accepts public HTTP requests and forwards them over QUIC to
//! the connected tunnel client.
//!
//! Requests are buffered in full so they can be replayed. While no client is
//! connected, or when the connection drops before a response head arrives, the
//! request waits and is retried on the next connection, until
//! `--request-timeout` expires (then the caller gets a 504).

mod identity;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use clap::Parser;
use quinn::crypto::rustls::QuicServerConfig;
use tokio::sync::watch;
use tokio::time::{Instant, sleep, timeout_at};
use tokio_util::io::ReaderStream;
use tracing::{debug, info, warn};
use tunnel_common::protocol::{
    RequestHead, ResponseHead, headers_from_wire, headers_to_wire, read_frame, write_frame,
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
    /// Current tunnel connection, `None` while no client is connected.
    conn: watch::Receiver<Option<quinn::Connection>>,
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
    let identity = identity::load_or_generate(&args.cert, &args.key)?;
    if args.print_fingerprint {
        println!("{}", identity.fingerprint);
        return Ok(());
    }
    info!(fingerprint = %identity.fingerprint, "server public key (pass to client as --server-pin)");

    let endpoint = quinn::Endpoint::server(quic_server_config(identity)?, args.quic_listen)
        .context("binding QUIC endpoint")?;
    info!(addr = %args.quic_listen, "QUIC listening");

    let (conn_tx, conn_rx) = watch::channel(None);
    tokio::spawn(accept_tunnels(endpoint, conn_tx));

    let state = AppState {
        conn: conn_rx,
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

fn quic_server_config(identity: identity::Identity) -> Result<quinn::ServerConfig> {
    let mut tls =
        rustls::ServerConfig::builder_with_provider(tunnel_common::tls::crypto_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(identity.certs, identity.key)?;
    tls.alpn_protocols = vec![tunnel_common::ALPN.to_vec()];

    let mut config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    let transport = Arc::get_mut(&mut config.transport).expect("fresh transport config");
    // Only the server opens streams.
    transport.max_concurrent_bidi_streams(0u32.into());
    transport.max_concurrent_uni_streams(0u32.into());
    transport.max_idle_timeout(Some(Duration::from_secs(15).try_into()?));
    Ok(config)
}

/// Accepts tunnel clients. The newest connection replaces any previous one.
async fn accept_tunnels(
    endpoint: quinn::Endpoint,
    conn_tx: watch::Sender<Option<quinn::Connection>>,
) {
    let conn_tx = Arc::new(conn_tx);
    while let Some(incoming) = endpoint.accept().await {
        let conn_tx = conn_tx.clone();
        tokio::spawn(async move {
            let remote = incoming.remote_address();
            let conn = match incoming.await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!(%remote, "tunnel handshake failed: {e}");
                    return;
                }
            };
            info!(%remote, id = conn.stable_id(), "tunnel client connected");
            if let Some(old) = conn_tx.send_replace(Some(conn.clone())) {
                old.close(0u32.into(), b"replaced by newer connection");
            }

            let reason = conn.closed().await;
            info!(%remote, id = conn.stable_id(), "tunnel client disconnected: {reason}");
            conn_tx.send_if_modified(|current| {
                let is_current = current
                    .as_ref()
                    .is_some_and(|c| c.stable_id() == conn.stable_id());
                if is_current {
                    *current = None;
                }
                is_current
            });
        });
    }
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
        Ok((resp_head, recv)) => build_response(resp_head, recv),
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
) -> (ResponseHead, quinn::RecvStream) {
    let mut conn_rx = state.conn.clone();
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        // Bind first so the non-Send watch guard is dropped before any await.
        let conn = conn_rx.wait_for(Option::is_some).await.map(|c| c.clone());
        let Ok(Some(conn)) = conn else {
            // Sender lives as long as the accept loop; nothing to wait for.
            return std::future::pending().await;
        };

        match try_forward(&conn, head, body).await {
            Ok(result) => return result,
            Err(e) => {
                warn!(attempt, method = %head.method, uri = %head.uri, "tunnel attempt failed, retrying: {e:#}");
                sleep(RETRY_DELAY).await;
            }
        }
    }
}

async fn try_forward(
    conn: &quinn::Connection,
    head: &RequestHead,
    body: &Bytes,
) -> Result<(ResponseHead, quinn::RecvStream)> {
    let (mut send, mut recv) = conn.open_bi().await.context("opening stream")?;
    write_frame(&mut send, head)
        .await
        .context("sending request head")?;
    send.write_all(body).await.context("sending request body")?;
    send.finish()?;
    let resp_head: ResponseHead = read_frame(&mut recv)
        .await
        .context("reading response head")?;
    debug!(status = resp_head.status, uri = %head.uri, "response head received");
    Ok((resp_head, recv))
}

fn build_response(head: ResponseHead, recv: quinn::RecvStream) -> Response {
    let Ok(status) = StatusCode::from_u16(head.status) else {
        return (StatusCode::BAD_GATEWAY, "invalid upstream status\n").into_response();
    };
    let mut response = Response::new(Body::from_stream(ReaderStream::new(recv)));
    *response.status_mut() = status;
    *response.headers_mut() = headers_from_wire(&head.headers);
    response
}
