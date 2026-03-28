//! Proxy performance benchmarks
//!
//! Run with: cargo bench

use criterion::{criterion_group, criterion_main, Criterion};
use socks5_proxy_rs::proxy::{ProxyConfig, ProxyServer};
use std::sync::Once;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;

static INIT: Once = Once::new();
static mut PROXY_PORT: u16 = 0;
static mut ECHO_PORT: u16 = 0;

fn setup(rt: &Runtime) {
    INIT.call_once(|| {
        rt.block_on(async {
            let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let echo_port = echo_listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                loop {
                    if let Ok((mut stream, _)) = echo_listener.accept().await {
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 65536];
                            loop {
                                match stream.read(&mut buf).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        if stream.write_all(&buf[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                            }
                        });
                    }
                }
            });

            let config = ProxyConfig {
                port: 0,
                host: "127.0.0.1".to_string(),
                auth: None,
                vmess: None,
            };
            let server = ProxyServer::bind(config).await.unwrap();
            let proxy_port = server.local_addr().unwrap().port();
            tokio::spawn(async move { server.run().await.ok() });

            unsafe {
                PROXY_PORT = proxy_port;
                ECHO_PORT = echo_port;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        });
    });
}

async fn do_socks5_handshake() -> Option<TcpStream> {
    let (proxy_port, echo_port) = unsafe { (PROXY_PORT, ECHO_PORT) };
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .ok()?;

    stream.write_all(&[0x05, 0x01, 0x00]).await.ok()?;
    let mut reply = vec![0u8; 2];
    stream.read_exact(&mut reply).await.ok()?;

    stream
        .write_all(&[
            0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1,
            (echo_port >> 8) as u8,
            echo_port as u8,
        ])
        .await
        .ok()?;
    let mut reply = vec![0u8; 10];
    stream.read_exact(&mut reply).await.ok()?;

    Some(stream)
}

fn bench_handshake(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    setup(&rt);

    let mut group = c.benchmark_group("handshake");
    group.sample_size(50);
    group.warm_up_time(Duration::from_secs(1));

    group.bench_function("socks5", |b| {
        b.to_async(&rt).iter(|| async {
            if let Some(s) = do_socks5_handshake().await {
                drop(s);
            }
        });
    });

    group.bench_function("http_connect", |b| {
        b.to_async(&rt).iter(|| async {
            let proxy_port = unsafe { PROXY_PORT };
            let echo_port = unsafe { ECHO_PORT };
            if let Ok(mut stream) =
                TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).await
            {
                let req = format!(
                    "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                    echo_port
                );
                let _ = stream.write_all(req.as_bytes()).await;
                let mut reply = vec![0u8; 256];
                let _ = stream.read(&mut reply).await;
                drop(stream);
            }
        });
    });

    group.finish();
}

fn bench_throughput(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    setup(&rt);

    let mut group = c.benchmark_group("throughput");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));

    group.bench_function("data_10mb", |b| {
        b.to_async(&rt).iter(|| async {
            if let Some(mut s) = do_socks5_handshake().await {
                let chunk = vec![0x41u8; 64 * 1024];
                let total = 10 * 1024 * 1024;
                let mut written = 0;
                while written < total {
                    if s.write_all(&chunk).await.is_err() {
                        break;
                    }
                    written += chunk.len();
                }
                let _ = s.shutdown().await;
            }
        });
    });

    group.finish();
}

fn bench_concurrent(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    setup(&rt);

    let mut group = c.benchmark_group("concurrent");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));

    group.bench_function("100_connections", |b| {
        b.to_async(&rt).iter(|| async {
            let futs: Vec<_> = (0..100).map(|_| do_socks5_handshake()).collect();
            let sockets = futures_util::future::join_all(futs).await;
            for s in sockets.into_iter().flatten() {
                drop(s);
            }
        });
    });

    group.finish();
}

criterion_group!(benches, bench_handshake, bench_throughput, bench_concurrent);
criterion_main!(benches);
