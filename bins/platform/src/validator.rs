//! Validator mode - P2P Network Validator
//!
//! Runs a validator node that participates in consensus and evaluation.
//! Connects to platform-server for centralized weight calculation.
//!
//! This module delegates to the validator-node binary for the actual implementation.

use anyhow::Result;
use clap::Args;
use std::path::PathBuf;
use std::process::Command;
use tracing::{error, info};

/// Default owner hotkey (Platform Network subnet owner)
const DEFAULT_OWNER_HOTKEY: &str = "5GziQCcRpN8NCJktX343brnfuVe3w6gUYieeStXPD1Dag2At";

#[derive(Args, Debug)]
pub struct ValidatorArgs {
    /// Secret key or mnemonic (REQUIRED)
    #[arg(short, long, env = "VALIDATOR_SECRET_KEY", required = true)]
    pub secret_key: String,

    /// Listen address
    #[arg(short, long, default_value = "/ip4/0.0.0.0/tcp/9000")]
    pub listen: String,

    /// Bootstrap peer addresses (comma-separated)
    #[arg(short, long)]
    pub bootstrap: Option<String>,

    /// Data directory
    #[arg(short, long, default_value = "./data")]
    pub data_dir: PathBuf,

    /// Subnet owner public key
    #[arg(long, env = "SUDO_KEY", default_value = DEFAULT_OWNER_HOTKEY)]
    pub sudo_key: String,

    /// Initial stake amount in TAO
    #[arg(long, default_value = "1000")]
    pub stake: f64,

    /// Minimum stake required (in TAO)
    #[arg(long, env = "MIN_STAKE_TAO", default_value = "1000")]
    pub min_stake: f64,

    // === Bittensor Options ===
    /// Bittensor network endpoint
    #[arg(
        long,
        env = "SUBTENSOR_ENDPOINT",
        default_value = "wss://entrypoint-finney.opentensor.ai:443"
    )]
    pub subtensor_endpoint: String,

    /// Subnet UID (netuid)
    #[arg(long, env = "NETUID", default_value = "100")]
    pub netuid: u16,

    /// Disable Bittensor connection (local testing)
    #[arg(long)]
    pub no_bittensor: bool,

    // === Epoch Options ===
    /// Blocks per epoch
    #[arg(long, default_value = "100")]
    pub epoch_length: u64,

    // === RPC Options ===
    /// RPC server port
    #[arg(long, default_value = "8080")]
    pub rpc_port: u16,

    // === Platform Server Integration ===
    /// Platform server URL for centralized orchestration
    #[arg(long, env = "PLATFORM_SERVER_URL")]
    pub platform_server: Option<String>,

    // === Docker Options ===
    /// Enable Docker challenge orchestration
    #[arg(long, default_value = "true")]
    pub docker_challenges: bool,

    /// Container broker WebSocket port
    #[arg(long, env = "BROKER_WS_PORT", default_value = "8090")]
    pub broker_port: u16,
}

pub async fn run(args: ValidatorArgs) -> Result<()> {
    info!("Starting validator node via delegation...");

    // Build command line arguments for validator-node
    let mut cmd_args = vec![
        "--secret-key".to_string(),
        args.secret_key.clone(),
        "--listen".to_string(),
        args.listen.clone(),
        "--data-dir".to_string(),
        args.data_dir.display().to_string(),
        "--sudo-key".to_string(),
        args.sudo_key.clone(),
        "--stake".to_string(),
        args.stake.to_string(),
        "--min-stake".to_string(),
        args.min_stake.to_string(),
        "--subtensor-endpoint".to_string(),
        args.subtensor_endpoint.clone(),
        "--netuid".to_string(),
        args.netuid.to_string(),
        "--epoch-length".to_string(),
        args.epoch_length.to_string(),
        "--rpc-port".to_string(),
        args.rpc_port.to_string(),
        "--broker-port".to_string(),
        args.broker_port.to_string(),
    ];

    if args.no_bittensor {
        cmd_args.push("--no-bittensor".to_string());
    }

    if let Some(ref bootstrap) = args.bootstrap {
        cmd_args.push("--bootstrap".to_string());
        cmd_args.push(bootstrap.clone());
    }

    if let Some(ref platform_server) = args.platform_server {
        cmd_args.push("--platform-server".to_string());
        cmd_args.push(platform_server.clone());
    }

    // Try to find validator-node in various locations
    let validator_paths = [
        "validator-node",                // In PATH
        "/usr/local/bin/validator-node", // Standard install
        "./validator-node",              // Current directory
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../validator-node/target/release/validator-node"
        ),
    ];

    let mut found_path = None;
    for path in &validator_paths {
        if std::path::Path::new(path).exists() || which::which(path).is_ok() {
            found_path = Some(path.to_string());
            break;
        }
    }

    let validator_bin = match found_path {
        Some(p) => p,
        None => {
            // Default to expecting it in PATH
            "validator-node".to_string()
        }
    };

    info!(
        "Delegating to: {} {}",
        validator_bin,
        cmd_args.join(" ").replace(&args.secret_key, "***")
    );

    // Execute validator-node with the same arguments
    let status = Command::new(&validator_bin).args(&cmd_args).status();

    match status {
        Ok(exit_status) => {
            if exit_status.success() {
                Ok(())
            } else {
                Err(anyhow::anyhow!(
                    "validator-node exited with status: {}",
                    exit_status
                ))
            }
        }
        Err(e) => {
            error!("Failed to execute validator-node: {}", e);
            error!("");
            error!("Make sure validator-node is in your PATH or in /usr/local/bin/");
            error!("For Docker deployments, ensure both binaries are in the image.");
            Err(anyhow::anyhow!("Failed to start validator-node: {}", e))
        }
    }
}
