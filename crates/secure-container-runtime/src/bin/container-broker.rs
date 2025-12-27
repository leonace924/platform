//! Container Broker Daemon
//!
//! This is the ONLY process that should have access to the Docker socket.
//! It listens on a Unix socket AND/OR WebSocket and manages containers securely.
//!
//! Usage:
//!   container-broker [OPTIONS]
//!
//! Options:
//!   --socket PATH    Unix socket path (default: /var/run/platform/container-broker.sock)
//!   --ws-port PORT   WebSocket port (default: 8090, 0 to disable)
//!   --ws-only        Disable Unix socket, use WebSocket only
//!
//! Environment:
//!   BROKER_SOCKET      Unix socket path
//!   BROKER_WS_PORT     WebSocket port
//!   BROKER_JWT_SECRET  JWT secret for WebSocket auth (required for WS in production)
//!   BROKER_DEV_MODE    Enable development mode (relaxed policy)

use secure_container_runtime::{run_ws_server, ContainerBroker, SecurityPolicy, WsConfig};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

const DEFAULT_SOCKET: &str = "/var/run/platform/container-broker.sock";
const DEFAULT_WS_PORT: u16 = 8090;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .with_thread_ids(false)
        .compact()
        .init();

    info!("Container Broker starting...");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));

    // Parse arguments
    let args: Vec<String> = std::env::args().collect();
    let socket_path = parse_arg(&args, "--socket")
        .or_else(|| std::env::var("BROKER_SOCKET").ok())
        .unwrap_or_else(|| DEFAULT_SOCKET.to_string());

    let ws_port: u16 = parse_arg(&args, "--ws-port")
        .or_else(|| std::env::var("BROKER_WS_PORT").ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_WS_PORT);

    let ws_only = args.contains(&"--ws-only".to_string());

    // Load policy
    let policy = if std::env::var("BROKER_DEV_MODE").is_ok() {
        info!("Using development security policy");
        SecurityPolicy::development()
    } else {
        info!("Using strict security policy");
        SecurityPolicy::strict()
    };

    // Create broker
    let broker = Arc::new(ContainerBroker::with_policy(policy).await?);

    info!("Security policies:");
    info!("  - Only whitelisted images allowed");
    info!("  - Non-privileged containers only");
    info!("  - Docker socket mounting blocked");
    info!("  - Resource limits enforced");
    info!("  - Audit logging enabled");

    // Start WebSocket server if enabled
    let ws_handle = if ws_port > 0 {
        let ws_config = WsConfig {
            bind_addr: format!("0.0.0.0:{}", ws_port),
            jwt_secret: std::env::var("BROKER_JWT_SECRET").ok(),
            allowed_challenges: vec![],
            max_connections_per_challenge: 10,
        };

        if ws_config.jwt_secret.is_none() && std::env::var("BROKER_DEV_MODE").is_err() {
            info!("WARNING: WebSocket running without JWT auth (set BROKER_JWT_SECRET)");
        }

        info!("WebSocket server: ws://0.0.0.0:{}", ws_port);
        let broker_clone = broker.clone();
        Some(tokio::spawn(async move {
            if let Err(e) = run_ws_server(broker_clone, ws_config).await {
                tracing::error!(error = %e, "WebSocket server error");
            }
        }))
    } else {
        info!("WebSocket server: disabled");
        None
    };

    // Start Unix socket server if not ws-only
    if !ws_only {
        // Create socket directory if needed
        if let Some(parent) = PathBuf::from(&socket_path).parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
                info!("Created socket directory: {:?}", parent);
            }
        }

        info!("Unix socket: {}", socket_path);
        broker.run(&socket_path).await?;
    } else {
        info!("Unix socket: disabled (ws-only mode)");
        // Wait for WebSocket server
        if let Some(handle) = ws_handle {
            handle.await?;
        }
    }

    Ok(())
}

fn parse_arg(args: &[String], flag: &str) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == flag && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
    }
    None
}
