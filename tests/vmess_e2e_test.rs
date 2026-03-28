//! End-to-end test: local VMess server <-> our proxy client

use socks5_proxy_rs::proxy::{ProxyConfig, ProxyServer};
use socks5_proxy_rs::vmess::chunk::{ChunkDecoder, ChunkEncoder};
use socks5_proxy_rs::vmess::crypto::*;
use socks5_proxy_rs::vmess::vmess::{Network, Security, VMessUpstream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UUID: &str = "11111111-2222-3333-4444-555555555555";

fn cmd_key() -> [u8; 16] {
    let uuid_bytes = uuid_to_bytes(UUID);
    compute_cmd_key(&uuid_bytes)
}

// --- Mini VMess AEAD server ---
// Returns the port it bound to

async fn start_vmess_server(target_port: u16) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cmd_key = cmd_key();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            let cmd_key = cmd_key;
            let tp = target_port;

            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                let n = match stream.read(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => return,
                };
                let d = &buf[..n];

                // Parse VMess header
                let aid = &d[0..16];
                let cn = &d[34..42];

                let lk = vmess_kdf(&cmd_key, &[b"VMess Header AEAD Key_Length", aid, cn]);
                let li = vmess_kdf(&cmd_key, &[b"VMess Header AEAD Nonce_Length", aid, cn]);
                let il = match aead_open(
                    AeadAlgorithm::Aes128Gcm,
                    &lk[..16],
                    &li[..12],
                    &d[16..34],
                    Some(aid),
                ) {
                    Ok(plain) => u16::from_be_bytes([plain[0], plain[1]]) as usize,
                    Err(_) => return,
                };

                let pk = vmess_kdf(&cmd_key, &[b"VMess Header AEAD Key", aid, cn]);
                let pi = vmess_kdf(&cmd_key, &[b"VMess Header AEAD Nonce", aid, cn]);
                let ins = match aead_open(
                    AeadAlgorithm::Aes128Gcm,
                    &pk[..16],
                    &pi[..12],
                    &d[42..42 + il + 16],
                    Some(aid),
                ) {
                    Ok(plain) => plain,
                    Err(_) => return,
                };

                let mut o = 1;
                let iv = ins[o..o + 16].to_vec();
                o += 16;
                let ky = ins[o..o + 16].to_vec();
                o += 16;
                let rv = ins[o];

                let bk = ky;
                let bi = iv;
                let (rk, ri) = derive_response_body_key_iv(&bk, &bi, AeadAlgorithm::Aes128Gcm);

                let mut decoder = ChunkDecoder::new(&bk, &bi, AeadAlgorithm::Aes128Gcm);

                // Collect all client data: may be in initial packet or subsequent reads
                let ds = 42 + il + 16;
                let mut client_data = Vec::new();

                // Try to decode any data after the header
                if d.len() > ds {
                    if let Ok(chunks) = decoder.decode(&d[ds..]) {
                        for chunk in chunks {
                            client_data.extend_from_slice(&chunk);
                        }
                    }
                }

                // If no data yet, read more from the VMess client
                if client_data.is_empty() {
                    let mut extra_buf = vec![0u8; 65536];
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        stream.read(&mut extra_buf),
                    ).await {
                        Ok(Ok(n)) if n > 0 => {
                            if let Ok(chunks) = decoder.decode(&extra_buf[..n]) {
                                for chunk in chunks {
                                    client_data.extend_from_slice(&chunk);
                                }
                            }
                        }
                        _ => {}
                    }
                }

                if client_data.is_empty() {
                    return;
                }

                // Connect to target
                let mut target = match TcpStream::connect(format!("127.0.0.1:{}", tp)).await {
                    Ok(t) => t,
                    Err(_) => return,
                };

                let _ = target.write_all(&client_data).await;

                // Read response from target
                let mut resp_buf = vec![0u8; 65536];
                let rn = match target.read(&mut resp_buf).await {
                    Ok(n) if n > 0 => n,
                    _ => return,
                };

                // Build VMess response
                let resp_len_key = vmess_kdf(&rk, &[b"AEAD Resp Header Len Key"])[..16].to_vec();
                let resp_len_iv = vmess_kdf(&ri, &[b"AEAD Resp Header Len IV"])[..12].to_vec();
                let resp_hdr_key = vmess_kdf(&rk, &[b"AEAD Resp Header Key"])[..16].to_vec();
                let resp_hdr_iv = vmess_kdf(&ri, &[b"AEAD Resp Header IV"])[..12].to_vec();

                let len_buf = 4u16.to_be_bytes();
                let enc_len = aead_seal(
                    AeadAlgorithm::Aes128Gcm,
                    &resp_len_key,
                    &resp_len_iv,
                    &len_buf,
                    None,
                );
                let enc_hdr = aead_seal(
                    AeadAlgorithm::Aes128Gcm,
                    &resp_hdr_key,
                    &resp_hdr_iv,
                    &[rv, 0, 0, 0],
                    None,
                );
                let mut resp_encoder = ChunkEncoder::new(&rk, &ri, AeadAlgorithm::Aes128Gcm);
                let enc_body = resp_encoder.encode(&resp_buf[..rn]);

                let mut response = Vec::new();
                response.extend_from_slice(&enc_len);
                response.extend_from_slice(&enc_hdr);
                response.extend_from_slice(&enc_body);

                let _ = stream.write_all(&response).await;
                let _ = stream.flush().await;
            });
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    port
}

// --- Target HTTP server ---

async fn start_target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nHello VMess!\n",
                    )
                    .await;
                let _ = stream.flush().await;
            });
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    port
}

#[tokio::test]
async fn vmess_e2e_socks5() {
    let tp = start_target().await;
    let vp = start_vmess_server(tp).await;

    let config = ProxyConfig {
        port: 0,
        host: "127.0.0.1".to_string(),
        auth: None,
        vmess: Some(VMessUpstream {
            address: "127.0.0.1".to_string(),
            port: vp,
            uuid: UUID.to_string(),
            security: Security::Aes128Gcm,
            network: Network::Tcp,
            tls: false,
            ws_path: None,
            ws_host: None,
        }),
    };

    let server = ProxyServer::bind(config).await.unwrap();
    let proxy_port = server.local_addr().unwrap().port();
    tokio::spawn(async move { server.run().await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // SOCKS5 through VMess
    let mut conn = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .unwrap();

    // Greeting
    conn.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut reply = vec![0u8; 2];
    conn.read_exact(&mut reply).await.unwrap();

    // Connect to target via IPv4
    conn.write_all(&[
        0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1,
        (tp >> 8) as u8,
        tp as u8,
    ])
    .await
    .unwrap();
    let mut reply = vec![0u8; 10];
    conn.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00); // SUCCESS

    // Send HTTP request
    conn.write_all(b"GET /test HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    // Read response with timeout
    let mut response = Vec::new();
    let mut buf = vec![0u8; 4096];
    let read_result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        async {
            loop {
                match conn.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        response.extend_from_slice(&buf[..n]);
                        let s = String::from_utf8_lossy(&response);
                        if s.contains("Hello VMess!") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    ).await;

    assert!(read_result.is_ok(), "Timed out waiting for response");
    let response_str = String::from_utf8_lossy(&response);
    assert!(response_str.contains("HTTP/1.1 200 OK"), "Got: {}", response_str);
    assert!(response_str.contains("Hello VMess!"), "Got: {}", response_str);
}

#[tokio::test]
async fn vmess_e2e_http_connect() {
    let tp = start_target().await;
    let vp = start_vmess_server(tp).await;

    let config = ProxyConfig {
        port: 0,
        host: "127.0.0.1".to_string(),
        auth: None,
        vmess: Some(VMessUpstream {
            address: "127.0.0.1".to_string(),
            port: vp,
            uuid: UUID.to_string(),
            security: Security::Aes128Gcm,
            network: Network::Tcp,
            tls: false,
            ws_path: None,
            ws_host: None,
        }),
    };

    let server = ProxyServer::bind(config).await.unwrap();
    let proxy_port = server.local_addr().unwrap().port();
    tokio::spawn(async move { server.run().await.ok() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // HTTP CONNECT through VMess
    let mut conn = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .unwrap();

    let connect_req = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        tp
    );
    conn.write_all(connect_req.as_bytes()).await.unwrap();

    let mut reply = vec![0u8; 1024];
    let n = conn.read(&mut reply).await.unwrap();
    let reply_str = String::from_utf8_lossy(&reply[..n]);
    assert!(reply_str.contains("200"), "Got: {}", reply_str);

    // Send HTTP request through tunnel
    conn.write_all(b"GET /test HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    // Read response with timeout
    let mut response = Vec::new();
    let mut buf = vec![0u8; 4096];
    let read_result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        async {
            loop {
                match conn.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        response.extend_from_slice(&buf[..n]);
                        let s = String::from_utf8_lossy(&response);
                        if s.contains("Hello VMess!") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    ).await;

    assert!(read_result.is_ok(), "Timed out waiting for response");
    let response_str = String::from_utf8_lossy(&response);
    assert!(response_str.contains("HTTP/1.1 200 OK"), "Got: {}", response_str);
    assert!(response_str.contains("Hello VMess!"), "Got: {}", response_str);
}
