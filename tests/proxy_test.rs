//! SOCKS5 + HTTP proxy integration tests

use socks5_proxy_rs::proxy::{AuthConfig, ProxyConfig, ProxyServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn start_server(port: u16, auth: Option<AuthConfig>) -> u16 {
    let config = ProxyConfig {
        port,
        host: "127.0.0.1".to_string(),
        auth,
        vmess: None,
    };
    let server = ProxyServer::bind(config).await.unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        server.run().await.ok();
    });
    // Give the server a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    addr.port()
}

fn socks5_greeting(methods: &[u8]) -> Vec<u8> {
    let mut buf = vec![0x05, methods.len() as u8];
    buf.extend_from_slice(methods);
    buf
}

fn socks5_connect_request(host: &str, port: u16) -> Vec<u8> {
    let host_buf = host.as_bytes();
    let mut buf = vec![0x05, 0x01, 0x00, 0x03, host_buf.len() as u8];
    buf.extend_from_slice(host_buf);
    buf.push((port >> 8) as u8);
    buf.push(port as u8);
    buf
}

fn socks5_auth_packet(username: &str, password: &str) -> Vec<u8> {
    let u = username.as_bytes();
    let p = password.as_bytes();
    let mut buf = vec![0x01, u.len() as u8];
    buf.extend_from_slice(u);
    buf.push(p.len() as u8);
    buf.extend_from_slice(p);
    buf
}

async fn raw_connect(port: u16) -> TcpStream {
    TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .unwrap()
}

// ============================================================
// SOCKS5 — No Auth
// ============================================================

#[tokio::test]
async fn socks5_greeting_accepts_no_auth() {
    let port = start_server(23080, None).await;
    let mut conn = raw_connect(port).await;
    conn.write_all(&socks5_greeting(&[0x00])).await.unwrap();
    let mut reply = vec![0u8; 2];
    conn.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00);
}

#[tokio::test]
async fn socks5_greeting_rejects_unsupported() {
    let port = start_server(23081, None).await;
    let mut conn = raw_connect(port).await;
    conn.write_all(&socks5_greeting(&[0x03])).await.unwrap();
    let mut reply = vec![0u8; 2];
    conn.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0xff);
}

#[tokio::test]
async fn socks5_connect_domain() {
    let port = start_server(23082, None).await;
    let mut conn = raw_connect(port).await;

    conn.write_all(&socks5_greeting(&[0x00])).await.unwrap();
    let mut reply = vec![0u8; 2];
    conn.read_exact(&mut reply).await.unwrap();

    conn.write_all(&socks5_connect_request("httpbin.org", 80))
        .await
        .unwrap();
    let mut reply = vec![0u8; 10];
    conn.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00); // SUCCESS

    conn.write_all(b"GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = vec![0u8; 4096];
    let n = conn.read(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response[..n]);
    assert!(response_str.contains("HTTP/1.1 200"));
}

#[tokio::test]
async fn socks5_connect_ipv4() {
    let port = start_server(23083, None).await;
    let mut conn = raw_connect(port).await;

    conn.write_all(&socks5_greeting(&[0x00])).await.unwrap();
    let mut reply = vec![0u8; 2];
    conn.read_exact(&mut reply).await.unwrap();

    // Connect to 1.1.1.1:80
    let req = [
        0x05, 0x01, 0x00, 0x01, // VER CMD RSV ATYP_IPV4
        1, 1, 1, 1, // 1.1.1.1
        0x00, 0x50, // port 80
    ];
    conn.write_all(&req).await.unwrap();
    let mut reply = vec![0u8; 10];
    conn.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00);
}

#[tokio::test]
async fn socks5_rejects_bind_command() {
    let port = start_server(23084, None).await;
    let mut conn = raw_connect(port).await;

    conn.write_all(&socks5_greeting(&[0x00])).await.unwrap();
    let mut reply = vec![0u8; 2];
    conn.read_exact(&mut reply).await.unwrap();

    // CMD = 0x02 (BIND)
    let mut req = vec![0x05, 0x02, 0x00, 0x03, 4];
    req.extend_from_slice(b"test");
    req.extend_from_slice(&[0x00, 0x50]);
    conn.write_all(&req).await.unwrap();
    let mut reply = vec![0u8; 10];
    conn.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x07); // COMMAND NOT SUPPORTED
}

#[tokio::test]
async fn socks5_rejects_invalid_version() {
    let port = start_server(23085, None).await;
    let mut conn = raw_connect(port).await;
    conn.write_all(&[0x04, 0x01, 0x00]).await.unwrap(); // SOCKS4
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    // Should close without crash
}

// ============================================================
// SOCKS5 — With Auth
// ============================================================

#[tokio::test]
async fn socks5_auth_correct() {
    let port = start_server(
        23086,
        Some(AuthConfig {
            username: "user".to_string(),
            password: "pass".to_string(),
        }),
    )
    .await;
    let mut conn = raw_connect(port).await;

    conn.write_all(&socks5_greeting(&[0x02])).await.unwrap();
    let mut reply = vec![0u8; 2];
    conn.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x02);

    conn.write_all(&socks5_auth_packet("user", "pass"))
        .await
        .unwrap();
    let mut reply = vec![0u8; 2];
    conn.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00); // auth success
}

#[tokio::test]
async fn socks5_auth_wrong() {
    let port = start_server(
        23087,
        Some(AuthConfig {
            username: "user".to_string(),
            password: "pass".to_string(),
        }),
    )
    .await;
    let mut conn = raw_connect(port).await;

    conn.write_all(&socks5_greeting(&[0x02])).await.unwrap();
    let mut reply = vec![0u8; 2];
    conn.read_exact(&mut reply).await.unwrap();

    conn.write_all(&socks5_auth_packet("user", "wrong"))
        .await
        .unwrap();
    let mut reply = vec![0u8; 2];
    conn.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x01); // auth failure
}

#[tokio::test]
async fn socks5_no_auth_rejected_when_required() {
    let port = start_server(
        23088,
        Some(AuthConfig {
            username: "user".to_string(),
            password: "pass".to_string(),
        }),
    )
    .await;
    let mut conn = raw_connect(port).await;

    conn.write_all(&socks5_greeting(&[0x00])).await.unwrap();
    let mut reply = vec![0u8; 2];
    conn.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0xff); // NO ACCEPTABLE
}

// ============================================================
// HTTP CONNECT
// ============================================================

#[tokio::test]
async fn http_connect_tunnel() {
    let port = start_server(23089, None).await;
    let mut conn = raw_connect(port).await;

    conn.write_all(b"CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org:443\r\n\r\n")
        .await
        .unwrap();
    let mut reply = vec![0u8; 1024];
    let n = conn.read(&mut reply).await.unwrap();
    let reply_str = String::from_utf8_lossy(&reply[..n]);
    assert!(reply_str.contains("200 Connection Established"));
}

#[tokio::test]
async fn http_connect_auth_correct() {
    let port = start_server(
        23090,
        Some(AuthConfig {
            username: "user".to_string(),
            password: "pass".to_string(),
        }),
    )
    .await;
    let mut conn = raw_connect(port).await;

    let creds = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"user:pass",
    );
    let req = format!(
        "CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org\r\nProxy-Authorization: Basic {}\r\n\r\n",
        creds
    );
    conn.write_all(req.as_bytes()).await.unwrap();
    let mut reply = vec![0u8; 1024];
    let n = conn.read(&mut reply).await.unwrap();
    let reply_str = String::from_utf8_lossy(&reply[..n]);
    assert!(reply_str.contains("200"));
}

#[tokio::test]
async fn http_connect_auth_missing_407() {
    let port = start_server(
        23091,
        Some(AuthConfig {
            username: "user".to_string(),
            password: "pass".to_string(),
        }),
    )
    .await;
    let mut conn = raw_connect(port).await;

    conn.write_all(b"CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
        .await
        .unwrap();
    let mut reply = vec![0u8; 1024];
    let n = conn.read(&mut reply).await.unwrap();
    let reply_str = String::from_utf8_lossy(&reply[..n]);
    assert!(reply_str.contains("407"));
}

#[tokio::test]
async fn http_connect_auth_wrong_407() {
    let port = start_server(
        23092,
        Some(AuthConfig {
            username: "user".to_string(),
            password: "pass".to_string(),
        }),
    )
    .await;
    let mut conn = raw_connect(port).await;

    let creds = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"user:wrong",
    );
    let req = format!(
        "CONNECT httpbin.org:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
        creds
    );
    conn.write_all(req.as_bytes()).await.unwrap();
    let mut reply = vec![0u8; 1024];
    let n = conn.read(&mut reply).await.unwrap();
    let reply_str = String::from_utf8_lossy(&reply[..n]);
    assert!(reply_str.contains("407"));
}

// ============================================================
// HTTP plain proxy
// ============================================================

#[tokio::test]
async fn http_plain_proxy_get() {
    let port = start_server(23093, None).await;
    let mut conn = raw_connect(port).await;

    conn.write_all(b"GET http://httpbin.org/get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut reply = vec![0u8; 8192];
    let n = conn.read(&mut reply).await.unwrap();
    let reply_str = String::from_utf8_lossy(&reply[..n]);
    assert!(reply_str.contains("HTTP/1.1 200"));
}

#[tokio::test]
async fn http_plain_proxy_strips_proxy_headers() {
    let port = start_server(23094, None).await;
    let mut conn = raw_connect(port).await;

    conn.write_all(b"GET http://httpbin.org/headers HTTP/1.1\r\nHost: httpbin.org\r\nProxy-Connection: keep-alive\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut reply = vec![0u8; 8192];
    let n = conn.read(&mut reply).await.unwrap();
    let reply_str = String::from_utf8_lossy(&reply[..n]).to_lowercase();
    assert!(reply_str.contains("http/1.1 200"));
    assert!(!reply_str.contains("proxy-connection"));
}

#[tokio::test]
async fn http_plain_invalid_url_400() {
    let port = start_server(23095, None).await;
    let mut conn = raw_connect(port).await;

    conn.write_all(b"GET not-a-url HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut reply = vec![0u8; 1024];
    let n = conn.read(&mut reply).await.unwrap();
    let reply_str = String::from_utf8_lossy(&reply[..n]);
    assert!(reply_str.contains("400"));
}

#[tokio::test]
async fn http_plain_auth_missing_407() {
    let port = start_server(
        23096,
        Some(AuthConfig {
            username: "user".to_string(),
            password: "pass".to_string(),
        }),
    )
    .await;
    let mut conn = raw_connect(port).await;

    conn.write_all(b"GET http://httpbin.org/get HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
        .await
        .unwrap();
    let mut reply = vec![0u8; 1024];
    let n = conn.read(&mut reply).await.unwrap();
    let reply_str = String::from_utf8_lossy(&reply[..n]);
    assert!(reply_str.contains("407"));
}

// ============================================================
// Protocol detection edge cases
// ============================================================

#[tokio::test]
async fn protocol_detection_garbage_closes() {
    let port = start_server(23097, None).await;
    let mut conn = raw_connect(port).await;
    conn.write_all(&[0x00, 0x01, 0x02]).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    // Should close without crash
}

#[tokio::test]
async fn protocol_detection_empty_no_crash() {
    let port = start_server(23098, None).await;
    let _conn = raw_connect(port).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    // Should not crash
}
