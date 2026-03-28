//! SOCKS5 + HTTP/HTTPS proxy server with protocol auto-detection

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::vmess::chunk::ChunkEncoder;
use crate::vmess::vmess::{ResponseHandler, VMessSession, VMessUpstream, build_request};

// --- SOCKS5 Constants (RFC 1928) ---

const SOCKS_VERSION: u8 = 0x05;
const AUTH_NO_AUTH: u8 = 0x00;
const AUTH_USERNAME_PASSWORD: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

// --- Config ---

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub port: u16,
    pub host: String,
    pub auth: Option<AuthConfig>,
    pub vmess: Option<VMessUpstream>,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub username: String,
    pub password: String,
}

// --- Server ---

pub struct ProxyServer {
    listener: TcpListener,
    config: Arc<ProxyConfig>,
    vmess_session: Option<Arc<VMessSession>>,
}

impl ProxyServer {
    pub async fn bind(config: ProxyConfig) -> std::io::Result<Self> {
        let addr = format!("{}:{}", config.host, config.port);
        let listener = TcpListener::bind(&addr).await?;

        let vmess_session = config.vmess.as_ref().map(|v| Arc::new(VMessSession::new(v.clone())));

        Ok(Self {
            listener,
            config: Arc::new(config),
            vmess_session,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn run(&self) -> std::io::Result<()> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            let config = self.config.clone();
            let vmess_session = self.vmess_session.clone();

            tokio::spawn(async move {
                if let Err(_) = handle_connection(stream, config, vmess_session).await {
                    // Connection error - silently ignore
                }
            });
        }
    }
}

// Separate function for creating server for tests (returns listener for accept loop)
pub async fn create_server(config: ProxyConfig) -> std::io::Result<ProxyServer> {
    ProxyServer::bind(config).await
}

// --- Connection Handler ---

async fn handle_connection(
    mut stream: TcpStream,
    config: Arc<ProxyConfig>,
    vmess_session: Option<Arc<VMessSession>>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let first_byte = buf[0];

    if first_byte == SOCKS_VERSION {
        // SOCKS5
        handle_socks5(stream, &buf[..n], &config, vmess_session).await
    } else if first_byte >= 0x41 && first_byte <= 0x5a {
        // HTTP
        handle_http(stream, &buf[..n], &config, vmess_session).await
    } else {
        // Unknown protocol
        Ok(())
    }
}

// ============================================================
// SOCKS5 Handlers
// ============================================================

async fn handle_socks5(
    mut stream: TcpStream,
    data: &[u8],
    config: &ProxyConfig,
    vmess_session: Option<Arc<VMessSession>>,
) -> std::io::Result<()> {
    let require_auth = config.auth.is_some();

    // Parse greeting
    if data.len() < 3 || data[0] != SOCKS_VERSION {
        return Ok(());
    }

    let nmethods = data[1] as usize;
    let methods = &data[2..2 + nmethods.min(data.len() - 2)];

    if require_auth {
        if methods.contains(&AUTH_USERNAME_PASSWORD) {
            stream.write_all(&[SOCKS_VERSION, AUTH_USERNAME_PASSWORD]).await?;

            // Read auth packet
            let mut auth_buf = vec![0u8; 513];
            let n = stream.read(&mut auth_buf).await?;
            if n < 5 || auth_buf[0] != 0x01 {
                stream.write_all(&[0x01, 0x01]).await?;
                return Ok(());
            }

            let ulen = auth_buf[1] as usize;
            let username = std::str::from_utf8(&auth_buf[2..2 + ulen])
                .unwrap_or("")
                .to_string();
            let plen = auth_buf[2 + ulen] as usize;
            let password = std::str::from_utf8(&auth_buf[3 + ulen..3 + ulen + plen])
                .unwrap_or("")
                .to_string();

            let auth = config.auth.as_ref().unwrap();
            if username == auth.username && password == auth.password {
                stream.write_all(&[0x01, 0x00]).await?;
            } else {
                stream.write_all(&[0x01, 0x01]).await?;
                return Ok(());
            }
        } else {
            stream.write_all(&[SOCKS_VERSION, AUTH_NO_ACCEPTABLE]).await?;
            return Ok(());
        }
    } else {
        if methods.contains(&AUTH_NO_AUTH) {
            stream.write_all(&[SOCKS_VERSION, AUTH_NO_AUTH]).await?;
        } else {
            stream.write_all(&[SOCKS_VERSION, AUTH_NO_ACCEPTABLE]).await?;
            return Ok(());
        }
    }

    // Read connect request
    let mut req_buf = vec![0u8; 263];
    let n = stream.read(&mut req_buf).await?;

    handle_socks_request(&mut stream, &req_buf[..n], vmess_session).await
}

async fn handle_socks_request(
    stream: &mut TcpStream,
    data: &[u8],
    vmess_session: Option<Arc<VMessSession>>,
) -> std::io::Result<()> {
    if data.len() < 7 || data[0] != SOCKS_VERSION {
        send_socks_reply(stream, REP_GENERAL_FAILURE).await?;
        return Ok(());
    }

    let cmd = data[1];
    if cmd != CMD_CONNECT {
        send_socks_reply(stream, REP_COMMAND_NOT_SUPPORTED).await?;
        return Ok(());
    }

    let atyp = data[3];
    let (host, port_offset) = match atyp {
        ATYP_IPV4 => {
            if data.len() < 10 {
                send_socks_reply(stream, REP_GENERAL_FAILURE).await?;
                return Ok(());
            }
            let host = format!("{}.{}.{}.{}", data[4], data[5], data[6], data[7]);
            (host, 8)
        }
        ATYP_DOMAIN => {
            let domain_len = data[4] as usize;
            if data.len() < 5 + domain_len + 2 {
                send_socks_reply(stream, REP_GENERAL_FAILURE).await?;
                return Ok(());
            }
            let host = std::str::from_utf8(&data[5..5 + domain_len])
                .unwrap_or("")
                .to_string();
            (host, 5 + domain_len)
        }
        ATYP_IPV6 => {
            if data.len() < 22 {
                send_socks_reply(stream, REP_GENERAL_FAILURE).await?;
                return Ok(());
            }
            let mut parts = Vec::new();
            for i in 0..8 {
                let val = u16::from_be_bytes([data[4 + i * 2], data[4 + i * 2 + 1]]);
                parts.push(format!("{:x}", val));
            }
            let host = parts.join(":");
            (host, 20)
        }
        _ => {
            send_socks_reply(stream, REP_ADDRESS_TYPE_NOT_SUPPORTED).await?;
            return Ok(());
        }
    };

    let port = u16::from_be_bytes([data[port_offset], data[port_offset + 1]]);

    // Connect to remote
    if let Some(session) = vmess_session {
        match connect_via_vmess(stream, &host, port, &session).await {
            Ok(()) => {}
            Err(_) => {
                let _ = send_socks_reply(stream, REP_HOST_UNREACHABLE).await;
            }
        }
    } else {
        match connect_direct(stream, &host, port, true).await {
            Ok(()) => {}
            Err(_) => {
                let _ = send_socks_reply(stream, REP_HOST_UNREACHABLE).await;
            }
        }
    }

    Ok(())
}

async fn send_socks_reply(stream: &mut TcpStream, rep: u8) -> std::io::Result<()> {
    stream
        .write_all(&[
            SOCKS_VERSION, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, // BND.ADDR
            0, 0, // BND.PORT
        ])
        .await
}

// ============================================================
// HTTP/HTTPS Proxy Handlers
// ============================================================

async fn handle_http(
    mut stream: TcpStream,
    initial_data: &[u8],
    config: &ProxyConfig,
    vmess_session: Option<Arc<VMessSession>>,
) -> std::io::Result<()> {
    // Check auth if required
    let mut buf = initial_data.to_vec();
    if let Some(auth) = &config.auth {
        if !check_http_auth(&mut stream, &buf, auth).await? {
            return Ok(());
        }
    }
    loop {
        let header_str = String::from_utf8_lossy(&buf);
        if let Some(header_end) = header_str.find("\r\n\r\n") {
            let first_line_end = header_str.find("\r\n").unwrap();
            let first_line = &header_str[..first_line_end];
            let parts: Vec<&str> = first_line.split(' ').collect();
            if parts.len() < 2 {
                return Ok(());
            }
            let method = parts[0];
            let target = parts[1];

            if method == "CONNECT" {
                return handle_connect(&mut stream, target, vmess_session).await;
            } else {
                return handle_plain_http(&mut stream, &buf, &header_str, header_end, vmess_session)
                    .await;
            }
        }

        let mut tmp = vec![0u8; 8192];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

async fn check_http_auth(
    stream: &mut TcpStream,
    data: &[u8],
    auth: &AuthConfig,
) -> std::io::Result<bool> {
    let header = String::from_utf8_lossy(data);

    // Find Proxy-Authorization header
    let auth_match = header
        .lines()
        .find(|line| line.to_lowercase().starts_with("proxy-authorization:"))
        .and_then(|line| {
            let value = line.splitn(2, ':').nth(1)?.trim();
            if value.to_lowercase().starts_with("basic ") {
                Some(value[6..].trim().to_string())
            } else {
                None
            }
        });

    match auth_match {
        None => {
            // No auth — send 407 challenge. iOS will retry on a new connection.
            stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n",
                )
                .await?;
            Ok(false)
        }
        Some(b64) => {
            let decoded = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &b64,
            )
            .unwrap_or_default();
            let decoded_str = String::from_utf8_lossy(&decoded);
            let mut parts = decoded_str.splitn(2, ':');
            let username = parts.next().unwrap_or("");
            let password = parts.next().unwrap_or("");

            if username == auth.username && password == auth.password {
                Ok(true)
            } else {
                stream
                    .write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n",
                    )
                    .await?;
                Ok(false)
            }
        }
    }
}

async fn handle_connect(
    stream: &mut TcpStream,
    target: &str,
    vmess_session: Option<Arc<VMessSession>>,
) -> std::io::Result<()> {
    let colon_idx = target.rfind(':');
    let (host, port_str) = match colon_idx {
        Some(idx) if idx > 0 => (&target[..idx], &target[idx + 1..]),
        _ => (target, "443"),
    };
    let port: u16 = port_str.parse().unwrap_or(443);

    if let Some(session) = vmess_session {
        // Send 200 first, then VMess
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        connect_via_vmess_forwarding(stream, host, port, &session).await
    } else {
        connect_direct(stream, host, port, false).await
    }
}

async fn handle_plain_http(
    stream: &mut TcpStream,
    raw_buf: &[u8],
    header_str: &str,
    header_end: usize,
    vmess_session: Option<Arc<VMessSession>>,
) -> std::io::Result<()> {
    let first_line_end = header_str.find("\r\n").unwrap();
    let first_line = &header_str[..first_line_end];
    let parts: Vec<&str> = first_line.split(' ').collect();
    let method = parts[0];
    let url_str = parts[1];
    let http_version = if parts.len() > 2 { parts[2] } else { "HTTP/1.1" };

    let parsed_url = match url::Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => {
            stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                .await?;
            return Ok(());
        }
    };

    let host = parsed_url.host_str().unwrap_or("").to_string();
    let port = parsed_url.port().unwrap_or(80);
    let path = if parsed_url.query().is_some() {
        format!("{}?{}", parsed_url.path(), parsed_url.query().unwrap())
    } else {
        parsed_url.path().to_string()
    };

    // Rewrite request: absolute URL -> relative path, remove proxy headers
    let rest_headers = &header_str[first_line_end..header_end + 4];
    let cleaned_headers: String = rest_headers
        .split("\r\n")
        .filter(|line| !line.to_lowercase().starts_with("proxy-"))
        .collect::<Vec<&str>>()
        .join("\r\n");

    let rewritten = format!("{} {} {}{}", method, path, http_version, cleaned_headers);
    let body_start = header_end + 4;
    let body = if raw_buf.len() > body_start {
        Some(&raw_buf[body_start..])
    } else {
        None
    };

    let mut request_data = rewritten.into_bytes();
    if let Some(body) = body {
        request_data.extend_from_slice(body);
    }

    // Connect and forward
    if let Some(session) = vmess_session {
        match connect_via_vmess_with_data(stream, &host, port, &session, &request_data).await {
            Ok(()) => {}
            Err(_) => {
                let _ = stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                    .await;
            }
        }
    } else {
        match TcpStream::connect(format!("{}:{}", host, port)).await {
            Ok(mut remote) => {
                remote.write_all(&request_data).await?;
                let _ = tokio::io::copy_bidirectional(stream, &mut remote).await;
            }
            Err(_) => {
                stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                    .await?;
            }
        }
    }

    Ok(())
}

// ============================================================
// Remote connection helpers
// ============================================================

async fn connect_direct(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    is_socks5: bool,
) -> std::io::Result<()> {
    let addr = format!("{}:{}", host, port);
    match TcpStream::connect(&addr).await {
        Ok(mut remote) => {
            if is_socks5 {
                send_socks_reply(stream, REP_SUCCESS).await?;
            } else {
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
            }
            let _ = tokio::io::copy_bidirectional(stream, &mut remote).await;
            Ok(())
        }
        Err(e) => {
            if is_socks5 {
                send_socks_reply(stream, REP_HOST_UNREACHABLE).await?;
            } else {
                stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                    .await?;
            }
            Err(e)
        }
    }
}

async fn connect_via_vmess(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    session: &VMessSession,
) -> std::io::Result<()> {
    let algo = session.config.security.aead_algo();
    let req = build_request(session, host, port);
    let mut encoder = ChunkEncoder::new(&req.request_body_key, &req.request_body_iv, algo);
    let mut response_handler = ResponseHandler::new(&req, algo);

    let addr = format!("{}:{}", session.config.address, session.config.port);
    let mut remote = TcpStream::connect(&addr).await?;

    // Send VMess header
    remote.write_all(&req.header_buf).await?;

    // Send SOCKS5 success reply
    send_socks_reply(stream, REP_SUCCESS).await?;

    // Bidirectional forwarding with VMess encoding/decoding
    vmess_bidirectional(stream, &mut remote, &mut encoder, &mut response_handler).await
}

async fn connect_via_vmess_forwarding(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    session: &VMessSession,
) -> std::io::Result<()> {
    let algo = session.config.security.aead_algo();
    let req = build_request(session, host, port);
    let mut encoder = ChunkEncoder::new(&req.request_body_key, &req.request_body_iv, algo);
    let mut response_handler = ResponseHandler::new(&req, algo);

    let addr = format!("{}:{}", session.config.address, session.config.port);
    let mut remote = TcpStream::connect(&addr).await?;

    remote.write_all(&req.header_buf).await?;

    vmess_bidirectional(stream, &mut remote, &mut encoder, &mut response_handler).await
}

async fn connect_via_vmess_with_data(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    session: &VMessSession,
    initial_data: &[u8],
) -> std::io::Result<()> {
    let algo = session.config.security.aead_algo();
    let req = build_request(session, host, port);
    let mut encoder = ChunkEncoder::new(&req.request_body_key, &req.request_body_iv, algo);
    let mut response_handler = ResponseHandler::new(&req, algo);

    let addr = format!("{}:{}", session.config.address, session.config.port);
    let mut remote = TcpStream::connect(&addr).await?;

    // Send header + initial data
    remote.write_all(&req.header_buf).await?;
    let encoded = encoder.encode(initial_data);
    remote.write_all(&encoded).await?;

    vmess_bidirectional(stream, &mut remote, &mut encoder, &mut response_handler).await
}

async fn vmess_bidirectional(
    stream: &mut TcpStream,
    remote: &mut TcpStream,
    encoder: &mut ChunkEncoder,
    response_handler: &mut ResponseHandler,
) -> std::io::Result<()> {
    let (mut client_reader, mut client_writer) = stream.split();
    let (mut remote_reader, mut remote_writer) = remote.split();

    let client_to_remote = async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match client_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let encoded = encoder.encode(&buf[..n]);
                    if remote_writer.write_all(&encoded).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };

    let remote_to_client = async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match remote_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => match response_handler.handle_data(&buf[..n]) {
                    Ok(chunks) => {
                        for chunk in chunks {
                            if client_writer.write_all(&chunk).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(_) => break,
                },
                Err(_) => break,
            }
        }
    };

    tokio::select! {
        _ = client_to_remote => {},
        _ = remote_to_client => {},
    }

    Ok(())
}
