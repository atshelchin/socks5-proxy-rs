use clap::Parser;
use socks5_proxy_rs::proxy::{AuthConfig, ProxyConfig, ProxyServer};
use socks5_proxy_rs::vmess::vmess::{Network, Security, VMessUpstream};

#[derive(Parser)]
#[command(name = "socks5-proxy-rs")]
#[command(about = "High-performance SOCKS5 + HTTP proxy with VMess upstream support")]
struct Cli {
    /// Listen port
    #[arg(short, long, default_value = "4080", env = "SOCKS5_PORT")]
    port: u16,

    /// Listen address
    #[arg(long, default_value = "0.0.0.0", env = "SOCKS5_HOST")]
    host: String,

    /// Auth username
    #[arg(short = 'u', long, env = "SOCKS5_USER")]
    user: Option<String>,

    /// Auth password
    #[arg(long, env = "SOCKS5_PASS")]
    pass: Option<String>,

    /// Enable VMess upstream (read URI from env VMESS, or pass vmess://... as value)
    #[arg(long)]
    vmess: Option<Option<String>>,
}

fn parse_vmess_uri(uri: &str) -> Option<VMessUpstream> {
    if uri.is_empty() {
        return None;
    }
    let b64 = uri.strip_prefix("vmess://").unwrap_or(uri);
    let json_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        b64,
    )
    .ok()?;
    let json: serde_json::Value = serde_json::from_slice(&json_bytes).ok()?;

    let scy = json["scy"].as_str().unwrap_or("auto");
    let security = match scy {
        "chacha20-poly1305" => Security::ChaCha20Poly1305,
        "none" => Security::None,
        _ => Security::Aes128Gcm, // "auto" or "aes-128-gcm"
    };

    let net = json["net"].as_str().unwrap_or("tcp");
    let network = if net == "ws" { Network::Ws } else { Network::Tcp };
    let tls = json["tls"].as_str() == Some("tls");

    Some(VMessUpstream {
        address: json["add"].as_str()?.to_string(),
        port: json["port"].as_u64().or_else(|| json["port"].as_str()?.parse().ok())? as u16,
        uuid: json["id"].as_str()?.to_string(),
        security,
        network,
        tls,
        ws_path: json["path"].as_str().map(|s| s.to_string()),
        ws_host: json["host"].as_str().map(|s| s.to_string()),
    })
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    // Parse VMess
    let vmess = match &cli.vmess {
        Some(Some(uri)) if uri.starts_with("vmess://") => parse_vmess_uri(uri),
        Some(_) => {
            // Read from env
            let env_vmess = std::env::var("VMESS").unwrap_or_default();
            parse_vmess_uri(&env_vmess)
        }
        None => None,
    };

    let config = ProxyConfig {
        port: cli.port,
        host: cli.host,
        auth: match (cli.user, cli.pass) {
            (Some(username), Some(password)) => Some(AuthConfig { username, password }),
            _ => None,
        },
        vmess,
    };

    let server = ProxyServer::bind(config.clone()).await?;
    let addr = server.local_addr()?;

    let mode = match &config.vmess {
        Some(v) => format!(
            "VMess → {}:{} ({:?}, {:?}{})",
            v.address,
            v.port,
            v.security,
            v.network,
            if v.tls { "+tls" } else { "" }
        ),
        None => "direct".to_string(),
    };

    println!(
        "Proxy listening on {} [SOCKS5 + HTTP] [upstream: {}] [auth: {}]",
        addr,
        mode,
        if config.auth.is_some() { "yes" } else { "no" }
    );

    // Graceful shutdown
    let server_handle = tokio::spawn(async move {
        server.run().await
    });

    tokio::signal::ctrl_c().await?;
    println!("\nShutting down...");

    server_handle.abort();
    Ok(())
}
