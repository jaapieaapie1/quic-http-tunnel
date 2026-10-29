//! Shared protocol, identity and TLS helpers for the QUIC HTTP tunnel.
//!
//! Every tunneled HTTP request travels over its own QUIC bidirectional
//! stream, opened by the server:
//!
//! ```text
//! server -> client: [u32 len][RequestHead json][body bytes ...]  FIN
//! client -> server: [u32 len][ResponseHead json][body bytes ...] FIN
//! ```

pub mod identity;
pub mod protocol;
pub mod session;
pub mod tls;

/// ALPN identifier negotiated on the QUIC connection.
pub const ALPN: &[u8] = b"quic-http-tunnel/1";
