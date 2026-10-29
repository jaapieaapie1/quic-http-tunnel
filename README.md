# quic-http-tunnel

Tunnels HTTP requests from a public server to a private destination over QUIC.

```text
 HTTP caller ──► tunnel-server ══QUIC══► tunnel-client ──► destination
                 (public)                (private, dials out)
```

- `server/`: accepts HTTP on `--http-listen` and QUIC on `--quic-listen`, the
  latter **only** from clients whose public key is pinned with `--client-pin`.
- `client/`: connects out to the server, trusting **only** the pinned server
  public key, and forwards each request to `--destination`.
- `common/`: wire protocol, key generation and the public-key-pinning TLS
  verifiers.

## Usage

Each side has its own key pair and pins the other's public key. Both
binaries create a self-signed certificate and key on first run
(`server.crt`/`server.key`, `client.crt`/`client.key`; change with `--cert`
and `--key`), and `--print-fingerprint` prints the pin and exits.

```sh
# On the server
cargo run -p tunnel-server -- --print-fingerprint   # -> <server-fingerprint>

# On the private side
cargo run -p tunnel-client -- --print-fingerprint   # -> <client-fingerprint>

# Then start both
cargo run -p tunnel-server -- \
  --http-listen 0.0.0.0:8080 --quic-listen 0.0.0.0:4433 \
  --client-pin <client-fingerprint>
cargo run -p tunnel-client -- \
  --server tunnel.example.com:4433 \
  --server-pin <server-fingerprint> \
  --destination http://127.0.0.1:3000
```

Every flag can also be set by environment variable (`TUNNEL_*`, see `--help`).

### Windows service

Building the client with the `windows-service` feature adds a `--service`
flag that runs it under the Service Control Manager:

```sh
cargo build --release -p tunnel-client --target x86_64-pc-windows-gnu --features windows-service
```

Install it with `--install` and the flags the service should run with, as admin:

```bat
tunnel-client.exe --install --server tunnel.example.com:4433 --server-pin <server-fingerprint> --destination http://127.0.0.1:3000
sc.exe start tunnel-client
```

This registers an auto-start `tunnel-client` service running as LocalSystem,
launched as `tunnel-client.exe --service` plus the given flags. Only flags
are carried over, not `TUNNEL_*` environment variables. To change the flags,
remove it with `sc.exe delete tunnel-client` and install again.

In service mode the working directory is the executable's directory, so the
default `client.crt`/`client.key` live next to it, and logs are appended to
`tunnel-client.log` there. Run `--print-fingerprint` once from that directory
to create the key and get the pin before starting the service.

## Trust model

Both sides authenticate with mutual TLS, using public key pins rather than a
CA. A pin is the SHA-256 of a certificate's SubjectPublicKeyInfo. CA chain,
hostname and expiry are ignored, but the handshake signatures are still
verified, so only the holder of a pinned private key can pass. Rotating a
certificate with the same key keeps its pin valid.

- The client accepts only the server key given in `--server-pin`.
- The server accepts only client keys listed in `--client-pin` (repeat the
  flag, or separate with commas in `TUNNEL_CLIENT_PIN`). It refuses to start
  without one. A client with any other key, or no certificate, fails the
  handshake and never becomes the active tunnel.

Pinning several client keys lets you rotate keys without downtime. All pinned
clients are equivalent: the newest connection takes over from the previous one.
A rejected client logs an error and keeps retrying with backoff.

## Multiple connections

By default the client uses one QUIC connection, which carries up to
`--max-concurrent` (default 1024) requests at once; further requests queue on
the server. Processing for a single connection also runs on roughly one core.
With `--max-connections N` the client opens another connection whenever
requests in flight reach 75% of `--max-concurrent` per open connection, up to
`N`. The server sends each request to the connection with the fewest requests
in flight. Extra connections stay open until they are lost, and are opened
again when load needs them.

All connections of one client run belong to one session. The client sends the
session id in the TLS server name (SNI), which the pinned verifiers otherwise
ignore: `<id>.new.quic-http-tunnel` starts a session and replaces all
connections of the previous one, as a single connection always did, and
`<id>.join.quic-http-tunnel` adds a connection to the current session. The
server rejects a join to any other session. Clients that send the old plain
`quic-http-tunnel` name each start a session of their own.

Update the server before using `--max-connections` above 1: an older server
treats every extra connection as a replacement.

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
