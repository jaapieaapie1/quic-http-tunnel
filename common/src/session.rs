//! Tunnel sessions. A client may keep several QUIC connections open at once,
//! all part of one session. The server spreads requests over the connections
//! of the current session, and a connection that starts a new session
//! replaces all others.
//!
//! The session travels in the TLS server name (SNI), which the pinned
//! verifiers otherwise ignore, so the server knows at handshake time whether a
//! connection starts a session or joins one:
//!
//! ```text
//! <16 hex digits>.new.quic-http-tunnel    starts session <id>
//! <16 hex digits>.join.quic-http-tunnel   adds a connection to session <id>
//! quic-http-tunnel                        older client, starts an anonymous session
//! ```

use std::fmt;
use std::hash::{BuildHasher, Hasher, RandomState};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Server name used by clients without sessions.
pub const BASE_NAME: &str = "quic-http-tunnel";

/// Application close code for a join to a session the server doesn't have.
pub const UNKNOWN_SESSION: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionId(pub u64);

impl SessionId {
    pub fn random() -> Self {
        // RandomState is seeded randomly per process; unique enough to tell
        // sessions of the same client key apart.
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        );
        Self(hasher.finish())
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Start the session, replacing any other.
    New,
    /// Add a connection to the session, which must be the server's current one.
    Join,
}

/// The server name a client sends for `session` and `role`.
pub fn server_name(session: SessionId, role: Role) -> String {
    let role = match role {
        Role::New => "new",
        Role::Join => "join",
    };
    format!("{session}.{role}.{BASE_NAME}")
}

/// Parses a server name sent by a client. `None` means an older client
/// without sessions.
pub fn parse_server_name(name: &str) -> Option<(SessionId, Role)> {
    let rest = name.strip_suffix(BASE_NAME)?.strip_suffix('.')?;
    let (id, role) = rest.split_once('.')?;
    let role = match role {
        "new" => Role::New,
        "join" => Role::Join,
        _ => return None,
    };
    if id.len() != 16 {
        return None;
    }
    let id = u64::from_str_radix(id, 16).ok()?;
    Some((SessionId(id), role))
}

/// Increments a shared counter while alive.
pub struct CountGuard(Arc<AtomicUsize>);

impl CountGuard {
    pub fn new(counter: &Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter.clone())
    }
}

impl Drop for CountGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_name_round_trips() {
        let id = SessionId(0x0123_4567_89ab_cdef);
        for role in [Role::New, Role::Join] {
            assert_eq!(parse_server_name(&server_name(id, role)), Some((id, role)));
        }
    }

    #[test]
    fn older_and_invalid_names_have_no_session() {
        for name in [
            BASE_NAME,
            "x.quic-http-tunnel",
            "0123456789abcdef.other.quic-http-tunnel",
            "0123.new.quic-http-tunnel",
            "0123456789abcdeg.new.quic-http-tunnel",
            "0123456789abcdef.new.example.com",
        ] {
            assert_eq!(parse_server_name(name), None, "{name}");
        }
    }
}
