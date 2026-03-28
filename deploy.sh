#!/bin/bash
# One-command deploy: ./deploy.sh user@host [-p port] [--vmess "vmess://..."]
#
# Examples:
#   ./deploy.sh root@1.2.3.4
#   ./deploy.sh root@1.2.3.4 -p 8080
#   ./deploy.sh root@1.2.3.4 --vmess "vmess://eyJ..."
#   ./deploy.sh root@1.2.3.4 -u admin --pass secret

set -e

if [ -z "$1" ] || [[ "$1" == -* ]]; then
  echo "Usage: ./deploy.sh user@host [-p proxy_port] [--vmess \"vmess://...\"]"
  exit 1
fi

SERVER="$1"; shift

# Parse optional args
PROXY_PORT=4080
VMESS_URI=""
AUTH_USER=""
AUTH_PASS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p) PROXY_PORT="$2"; shift 2 ;;
    -u) AUTH_USER="$2"; shift 2 ;;
    --pass) AUTH_PASS="$2"; shift 2 ;;
    --vmess) VMESS_URI="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="socks5-proxy-rs-linux"

# Cross-compile for Linux x86_64 if binary doesn't exist
if [ ! -f "$SCRIPT_DIR/target/x86_64-unknown-linux-musl/release/socks5-proxy-rs" ]; then
  echo "Cross-compiling for Linux x86_64..."
  cd "$SCRIPT_DIR"
  # Ensure the musl target is installed
  rustup target add x86_64-unknown-linux-musl 2>/dev/null || true
  cargo build --release --target x86_64-unknown-linux-musl
fi

BINARY_PATH="$SCRIPT_DIR/target/x86_64-unknown-linux-musl/release/socks5-proxy-rs"

# Generate remote install script
SETUP_SCRIPT=$(mktemp)
cat > "$SETUP_SCRIPT" << EOF
#!/bin/bash
set -e

sudo mv /tmp/socks5-proxy-rs /usr/local/bin/socks5-proxy-rs
sudo chmod +x /usr/local/bin/socks5-proxy-rs

sudo tee /etc/socks5-proxy-rs.env > /dev/null << 'CONF'
SOCKS5_PORT=$PROXY_PORT
SOCKS5_HOST=0.0.0.0
SOCKS5_USER=$AUTH_USER
SOCKS5_PASS=$AUTH_PASS
VMESS=$VMESS_URI
CONF

sudo tee /usr/local/bin/socks5-proxy-rs-start > /dev/null << 'WRAPPER'
#!/bin/bash
source /etc/socks5-proxy-rs.env 2>/dev/null || true
ARGS="-p \${SOCKS5_PORT:-4080} --host \${SOCKS5_HOST:-0.0.0.0}"
[ -n "\$SOCKS5_USER" ] && ARGS="\$ARGS -u \$SOCKS5_USER --pass \$SOCKS5_PASS"
[ -n "\$VMESS" ] && ARGS="\$ARGS --vmess \$VMESS"
exec /usr/local/bin/socks5-proxy-rs \$ARGS
WRAPPER
sudo chmod +x /usr/local/bin/socks5-proxy-rs-start

sudo tee /etc/systemd/system/socks5-proxy-rs.service > /dev/null << 'SVC'
[Unit]
Description=SOCKS5/HTTP Proxy (Rust)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/socks5-proxy-rs-start
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
SVC

sudo systemctl daemon-reload
sudo systemctl enable socks5-proxy-rs
sudo systemctl restart socks5-proxy-rs
sleep 1

echo ""
echo "========================================="
sudo systemctl is-active socks5-proxy-rs > /dev/null && echo "  Proxy running on :$PROXY_PORT" || echo "  Failed to start"
echo "  Config: /etc/socks5-proxy-rs.env"
echo "  Logs:   journalctl -u socks5-proxy-rs -f"
echo "========================================="
EOF

echo "Deploying to $SERVER ..."

# Upload binary + script
scp "$BINARY_PATH" "$SERVER:/tmp/socks5-proxy-rs"
scp "$SETUP_SCRIPT" "$SERVER:/tmp/socks5-proxy-rs-setup.sh"
rm "$SETUP_SCRIPT"

# Run setup with interactive SSH (supports sudo password prompt)
ssh -t "$SERVER" "bash /tmp/socks5-proxy-rs-setup.sh && rm /tmp/socks5-proxy-rs-setup.sh"

echo ""
echo "Done! Test it:"
echo "  curl -x socks5://$SERVER:$PROXY_PORT https://httpbin.org/get"
