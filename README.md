# socks5-proxy-rs

High-performance multi-protocol proxy server built with Rust + Tokio. Supports SOCKS5, HTTP, and HTTPS proxy on a single port with automatic protocol detection. Optional VMess (AEAD) upstream for encrypted tunneling.

Rust rewrite of [socks5-proxy](https://github.com/atshelchin/socks5-proxy) (Bun/TypeScript), with multi-core support and zero GC pauses.

## Features

- SOCKS5 proxy (RFC 1928, username/password auth)
- HTTP proxy (plain HTTP forwarding)
- HTTPS proxy (HTTP CONNECT tunneling)
- Single port, auto-detect protocol
- Optional VMess AEAD upstream (alterId=0)
  - TCP and WebSocket transport
  - TLS support
  - AES-128-GCM / ChaCha20-Poly1305
- Multi-threaded async (Tokio runtime, uses all CPU cores)
- Compiles to single static binary (~5 MB)
- One-command deploy to Linux server

## Quick Start

```bash
cargo run
```

Proxy listens on `0.0.0.0:4080` by default.

## CLI

```bash
socks5-proxy-rs [options]
```

| Option | Description |
|--------|-------------|
| `-p, --port <port>` | Listen port (default: 4080) |
| `--host <host>` | Listen address (default: 0.0.0.0) |
| `-u, --user <user>` | Auth username |
| `--pass <pass>` | Auth password |
| `--vmess` | Enable VMess upstream (read URI from env `VMESS`) |
| `--vmess vmess://...` | Enable VMess with given URI |
| `--help` | Show help |

Environment variables: `SOCKS5_PORT`, `SOCKS5_HOST`, `SOCKS5_USER`, `SOCKS5_PASS`, `VMESS`

### Examples

```bash
# Direct proxy
cargo run

# Custom port + auth
cargo run -- -p 8080 -u admin --pass secret

# VMess upstream with URI
cargo run -- --vmess "vmess://eyJ..."

# Release build
cargo build --release
./target/release/socks5-proxy-rs -p 4080
```

### Client usage

```bash
# Without auth
curl -x socks5://127.0.0.1:4080 https://httpbin.org/get
curl -x http://127.0.0.1:4080 https://httpbin.org/get

# With auth
curl -x socks5://user:pass@127.0.0.1:4080 https://httpbin.org/get
curl -x http://user:pass@127.0.0.1:4080 https://httpbin.org/get
```

> **Note**: iOS system WiFi proxy settings do not send `Proxy-Authorization` for HTTPS CONNECT requests. To use auth from iPhone, use a third-party client (e.g. Shadowrocket) with SOCKS5 protocol, which fully supports username/password authentication.

## Build

```bash
# Debug
cargo build

# Release (optimized)
cargo build --release

# Static Linux binary (for deployment)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## Deploy to Server

One command — cross-compiles, uploads, installs as systemd service:

```bash
# Direct proxy
./deploy.sh root@1.2.3.4

# Custom port
./deploy.sh root@1.2.3.4 -p 8080

# With auth
./deploy.sh root@1.2.3.4 -u admin --pass secret

# With VMess upstream
./deploy.sh root@1.2.3.4 --vmess "vmess://eyJ..."
```

After deploy:

```bash
systemctl status socks5-proxy-rs      # Check status
systemctl restart socks5-proxy-rs     # Restart
journalctl -u socks5-proxy-rs -f      # View logs
vi /etc/socks5-proxy-rs.env           # Edit config
```

## Development

```bash
cargo run              # Start dev server
cargo test             # Run tests (53 tests)
cargo bench            # Performance benchmark
```

## Tests

53 tests covering all functionality:

| Category | Count |
|----------|-------|
| Crypto primitives (UUID, CmdKey, CRC32, FNV-1a) | 6 |
| VMess KDF (nested HMAC-SHA256) | 5 |
| AEAD seal/open (AES-128-GCM) | 4 |
| AuthID generation & validation | 3 |
| Key derivation (request/response body) | 3 |
| Chunk encoder/decoder | 5 |
| VMess request building & decryption | 6 |
| SOCKS5 proxy (no-auth + auth + edge cases) | 9 |
| HTTP/HTTPS proxy (CONNECT + plain + auth) | 8 |
| Protocol detection edge cases | 2 |
| VMess E2E (SOCKS5 + HTTP CONNECT via local VMess server) | 2 |

## Performance

Benchmarked on Apple Silicon (local loopback, release build):

| Metric | Rust | Bun (original) |
|--------|------|----------------|
| SOCKS5 handshake | ~2,300 conn/s | ~6,200 conn/s |
| HTTP CONNECT | ~2,000 conn/s | ~7,200 conn/s |
| 100 concurrent connections | 3.98 ms | ~15 ms (est.) |
| Binary size | ~5 MB | ~50 MB |

Single-connection latency is higher due to per-connection task spawn overhead. However, Rust scales linearly with CPU cores:

| Cores | Rust (projected) | Bun (single-threaded) |
|-------|------------------|-----------------------|
| 1 | ~2,300 conn/s | ~6,200 conn/s |
| 4 | ~9,200 conn/s | ~6,200 conn/s |
| 8 | ~18,400 conn/s | ~6,200 conn/s |
| 16 | ~36,800 conn/s | ~6,200 conn/s |

Additional Rust advantages:
- Zero GC pauses — stable P99 latency under load
- Lower memory footprint — no JS heap overhead
- Memory safety — no data races or buffer overflows at compile time

## Project Structure

```
Cargo.toml
deploy.sh             # One-command server deploy
src/
  main.rs             # CLI entry point (clap)
  lib.rs              # Module exports
  proxy.rs            # Core proxy (SOCKS5 + HTTP, protocol detection)
  vmess/
    mod.rs
    crypto.rs         # KDF, AEAD, AuthID, FNV1a, CRC32
    chunk.rs          # Chunked AEAD stream encoder/decoder
    vmess.rs          # VMess protocol (session, request builder, response handler)
tests/
  proxy_test.rs       # Proxy integration tests (19)
  vmess_e2e_test.rs   # E2E with local VMess server (2)
benches/
  proxy_bench.rs      # Criterion benchmarks
```
