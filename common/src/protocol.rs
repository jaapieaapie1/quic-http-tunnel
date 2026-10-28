use anyhow::{Context, Result, bail};
use http::HeaderMap;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Upper bound for an encoded head frame, protects against garbage input.
const MAX_FRAME_LEN: u32 = 1024 * 1024;

pub type Headers = Vec<(String, Vec<u8>)>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestHead {
    pub method: String,
    /// Path and query, e.g. `/api/items?page=2`.
    pub uri: String,
    pub headers: Headers,
    /// Exact body length that follows the head. Lets the receiver detect a
    /// truncated body when the sender gave up halfway.
    pub body_len: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseHead {
    pub status: u16,
    pub headers: Headers,
}

pub async fn write_frame<W, T>(w: &mut W, value: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let buf = serde_json::to_vec(value)?;
    let len = u32::try_from(buf.len()).context("frame too large")?;
    if len > MAX_FRAME_LEN {
        bail!("frame too large: {len} bytes");
    }
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&buf).await?;
    Ok(())
}

pub async fn read_frame<R, T>(r: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let len = r.read_u32().await.context("reading frame length")?;
    if len > MAX_FRAME_LEN {
        bail!("frame too large: {len} bytes");
    }
    let mut buf = vec![0; len as usize];
    r.read_exact(&mut buf).await.context("reading frame")?;
    Ok(serde_json::from_slice(&buf)?)
}

/// Hop-by-hop headers (RFC 9110 §7.6.1) apply to a single connection and must
/// not be forwarded.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Converts a header map to the wire representation, dropping hop-by-hop
/// headers, any header listed in `Connection`, and any name in `extra_skip`.
pub fn headers_to_wire(map: &HeaderMap, extra_skip: &[&str]) -> Headers {
    let connection_listed: Vec<String> = map
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .collect();

    map.iter()
        .filter(|(name, _)| {
            let name = name.as_str();
            !HOP_BY_HOP.contains(&name)
                && !extra_skip.contains(&name)
                && !connection_listed.iter().any(|c| c == name)
        })
        .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
        .collect()
}

/// Converts wire headers back to a header map, skipping invalid entries.
pub fn headers_from_wire(headers: &Headers) -> HeaderMap {
    let mut map = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_bytes(value),
        ) {
            map.append(name, value);
        }
    }
    map
}
