# quic-http-tunnel

Tunnels HTTP requests from a public server to a private destination over QUIC.

```text
 HTTP caller ──► tunnel-server ══QUIC══► tunnel-client ──► destination
                 (public)                (private, dials out)
```

- `server/`: accepts HTTP on `--http-listen` and QUIC on `--quic-listen`.
- `client/`: connects out to the server, trusting **only** the pinned server
  public key, and forwards each request to `--destination`.
- `common/`: wire protocol and the public-key-pinning TLS verifier.

## Usage

```sh
# On the server: creates server.crt/server.key on first run and prints the pin
cargo run -p tunnel-server -- --print-fingerprint
cargo run -p tunnel-server -- --http-listen 0.0.0.0:8080 --quic-listen 0.0.0.0:4433

# On the private side
cargo run -p tunnel-client -- \
  --server tunnel.example.com:4433 \
  --server-pin <fingerprint> \
  --destination http://127.0.0.1:3000
```

Every flag can also be set by environment variable (`TUNNEL_*`, see `--help`).

## Trust model

The client pins the SHA-256 of the server certificate's SubjectPublicKeyInfo.
CA chain, hostname and expiry are ignored; the handshake signature is still
verified, so only the holder of the private key can pass. Rotating the
certificate with the same key keeps the pin valid.

The server does **not** authenticate the client: anyone who can reach the QUIC
port can connect as the tunnel client, and the newest connection takes over.

## Reliability

- The client reconnects with exponential backoff (0.5s up to 10s). A dead
  connection is detected after `--idle-timeout` (default 10s) without traffic;
  keepalives are sent at a third of that interval.
- The server buffers each request body (`--max-body`, default 16 MiB). While no
  client is connected, or if the connection drops before the response head
  arrives, the request waits and is retried on the next connection.
- After `--request-timeout` (default 30s) without a response head, the
  caller gets `504 Gateway Timeout`.
- Once the response has started streaming it cannot be retried. If the
  connection drops midway, the caller's HTTP connection is aborted.
- The retry is at-least-once: if the connection dies after the client forwarded
  a request but before the response came back, the destination may receive
  the request twice. Keep this in mind for non-idempotent endpoints.
- If the destination can't be reached, the client returns `502 Bad Gateway`.
  That counts as a response and is not retried.
