//! Chain Sudo (csudo) - Administrative CLI for Platform Chain
//!
//! Provides subnet owners with administrative commands for managing
//! challenges, validators, and network configuration.

use anyhow::Result;
use clap::{Parser, Subcommand};
use parking_lot::RwLock;
use platform_consensus::PBFTEngine;
use platform_core::{
    ChainState, ChallengeContainerConfig, ChallengeId, Hotkey, Keypair, NetworkConfig,
    SignedNetworkMessage, Stake, SudoAction, ValidatorInfo,
};
// NetworkNode no longer needed - using RPC for broadcast
// use platform_network::{NetworkNode, NodeConfig};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "csudo")]
#[command(about = "Platform Chain administrative CLI for subnet owners")]
struct Args {
    /// Secret key or mnemonic (REQUIRED - subnet owner must be registered)
    /// Can be hex encoded 32 bytes or BIP39 mnemonic phrase
    #[arg(short, long, env = "SUDO_SECRET_KEY", required = true)]
    secret_key: String,

    /// Network peer to connect to (P2P)
    #[arg(short, long, default_value = "/ip4/127.0.0.1/tcp/9000")]
    peer: String,

    /// RPC server URL for queries
    #[arg(
        short,
        long,
        default_value = "https://chain.platform.network",
        env = "PLATFORM_RPC"
    )]
    rpc: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new keypair
    GenerateKey,

    /// Add a challenge (Docker container)
    AddChallenge {
        /// Challenge name
        #[arg(short, long)]
        name: String,

        /// Docker image (e.g., "cortexlm/term-bench:v1.0.0")
        #[arg(short, long)]
        docker_image: String,

        /// Mechanism ID on Bittensor (1, 2, 3... - each challenge needs unique ID)
        #[arg(short, long)]
        mechanism_id: u8,

        /// Timeout in seconds
        #[arg(long, default_value = "3600")]
        timeout: u64,

        /// Emission weight (0.0 - 1.0)
        #[arg(long, default_value = "1.0")]
        emission_weight: f64,

        /// CPU cores
        #[arg(long, default_value = "2.0")]
        cpu_cores: f64,

        /// Memory in MB
        #[arg(long, default_value = "4096")]
        memory_mb: u64,

        /// Requires GPU
        #[arg(long, default_value = "false")]
        gpu: bool,
    },

    /// Update a challenge (new Docker image)
    UpdateChallenge {
        /// Challenge ID (UUID)
        #[arg(short, long)]
        id: String,

        /// New Docker image
        #[arg(short, long)]
        docker_image: String,
    },

    /// Remove a challenge
    RemoveChallenge {
        /// Challenge ID (UUID)
        #[arg(short, long)]
        id: String,
    },

    /// Set required validator version
    SetVersion {
        /// Minimum required version (e.g., "0.2.0")
        #[arg(short, long)]
        version: String,

        /// Docker image for validators
        #[arg(short, long)]
        docker_image: String,

        /// Mandatory update (validators must update)
        #[arg(long, default_value = "false")]
        mandatory: bool,

        /// Deadline block (optional)
        #[arg(long)]
        deadline_block: Option<u64>,
    },

    /// List challenges (query from network)
    ListChallenges,

    /// Add a validator
    AddValidator {
        /// Validator hotkey (hex)
        #[arg(short, long)]
        hotkey: String,

        /// Stake amount in TAO
        #[arg(short, long, default_value = "10")]
        stake: f64,
    },

    /// Remove a validator
    RemoveValidator {
        /// Validator hotkey (hex)
        #[arg(short, long)]
        hotkey: String,
    },

    /// Update network configuration
    UpdateConfig {
        /// Minimum stake in TAO
        #[arg(long)]
        min_stake: Option<f64>,

        /// Consensus threshold (0.0-1.0)
        #[arg(long)]
        threshold: Option<f64>,

        /// Block time in milliseconds
        #[arg(long)]
        block_time: Option<u64>,
    },

    /// Emergency pause the network
    Pause {
        /// Reason for pause
        #[arg(short, long)]
        reason: String,
    },

    /// Resume the network
    Resume,

    /// Show network status
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let args = Args::parse();

    // Handle generate-key command separately
    if let Commands::GenerateKey = args.command {
        let keypair = Keypair::generate();
        println!("Generated new keypair:");
        println!("  Hotkey (public): {}", keypair.hotkey().to_hex());
        println!("  Secret key:      {}", hex::encode(keypair.secret_bytes()));
        return Ok(());
    }

    // Parse secret key (hex or mnemonic)
    let keypair = {
        let secret = &args.secret_key;

        // Strip 0x prefix if present
        let hex_str = secret.strip_prefix("0x").unwrap_or(secret);

        // Try hex decode first
        if let Ok(bytes) = hex::decode(hex_str) {
            if bytes.len() != 32 {
                anyhow::bail!("Hex secret key must be 32 bytes");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            info!("Loaded keypair from hex secret");
            Keypair::from_bytes(&arr)?
        } else {
            // Assume it's a mnemonic phrase - derive keypair from it
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            secret.hash(&mut hasher);
            let hash1 = hasher.finish();
            secret.chars().rev().collect::<String>().hash(&mut hasher);
            let hash2 = hasher.finish();

            let mut arr = [0u8; 32];
            arr[..8].copy_from_slice(&hash1.to_le_bytes());
            arr[8..16].copy_from_slice(&hash2.to_le_bytes());
            arr[16..24].copy_from_slice(&hash1.to_be_bytes());
            arr[24..32].copy_from_slice(&hash2.to_be_bytes());

            info!("Derived keypair from mnemonic phrase");
            Keypair::from_bytes(&arr)?
        }
    };

    info!("Subnet owner hotkey: {}", keypair.hotkey());

    // Create a temporary chain state (we'll sync from network)
    let chain_state = Arc::new(RwLock::new(ChainState::new(
        keypair.hotkey(),
        NetworkConfig::default(),
    )));

    // Create message channel
    let (msg_tx, mut msg_rx) = mpsc::channel::<SignedNetworkMessage>(100);

    // Create consensus engine
    let consensus = PBFTEngine::new(keypair.clone(), chain_state.clone(), msg_tx);

    // Execute command
    let action = match args.command {
        Commands::GenerateKey => unreachable!(),

        Commands::AddChallenge {
            name,
            docker_image,
            mechanism_id,
            timeout,
            emission_weight,
            cpu_cores,
            memory_mb,
            gpu,
        } => {
            let config = ChallengeContainerConfig {
                challenge_id: ChallengeId::new(),
                name: name.clone(),
                docker_image: docker_image.clone(),
                mechanism_id,
                emission_weight,
                timeout_secs: timeout,
                cpu_cores,
                memory_mb,
                gpu_required: gpu,
            };

            info!(
                "Adding challenge: {} (image: {}, mechanism: {})",
                name, docker_image, mechanism_id
            );
            SudoAction::AddChallenge { config }
        }

        Commands::UpdateChallenge { id, docker_image } => {
            let challenge_id = ChallengeId(uuid::Uuid::parse_str(&id)?);
            info!("Updating challenge {} to image {}", id, docker_image);

            // Create a minimal config for update
            let config = ChallengeContainerConfig {
                challenge_id,
                name: format!("challenge-{}", &id[..8]),
                docker_image,
                mechanism_id: 1,
                emission_weight: 1.0,
                timeout_secs: 3600,
                cpu_cores: 2.0,
                memory_mb: 4096,
                gpu_required: false,
            };

            SudoAction::UpdateChallenge { config }
        }

        Commands::RemoveChallenge { id } => {
            let challenge_id = ChallengeId(uuid::Uuid::parse_str(&id)?);
            info!("Removing challenge: {}", id);
            SudoAction::RemoveChallenge { id: challenge_id }
        }

        Commands::SetVersion {
            version,
            docker_image,
            mandatory,
            deadline_block,
        } => {
            info!(
                "Setting required version: {} (mandatory: {})",
                version, mandatory
            );
            SudoAction::SetRequiredVersion {
                min_version: version.clone(),
                recommended_version: version,
                docker_image,
                mandatory,
                deadline_block,
                release_notes: None,
            }
        }

        Commands::ListChallenges => {
            let client = reqwest::Client::new();
            let rpc_url = format!("{}/rpc", args.rpc.trim_end_matches('/'));

            let response = client
                .post(&rpc_url)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "chain_getState",
                    "params": [],
                    "id": 1
                }))
                .send()
                .await?;

            let result: serde_json::Value = response.json().await?;

            if let Some(error) = result.get("error") {
                eprintln!("RPC Error: {}", error);
                return Ok(());
            }

            if let Some(state) = result.get("result") {
                println!("=== Challenges ===");
                if let Some(challenges) = state.get("challenges") {
                    if let Some(obj) = challenges.as_object() {
                        if obj.is_empty() {
                            println!("No challenges registered.");
                        } else {
                            for (id, challenge) in obj {
                                println!("\nID: {}", id);
                                if let Some(name) = challenge.get("name") {
                                    println!("  Name: {}", name);
                                }
                                if let Some(desc) = challenge.get("description") {
                                    println!("  Description: {}", desc);
                                }
                            }
                        }
                    }
                }

                if let Some(configs) = state.get("challenge_configs") {
                    if let Some(obj) = configs.as_object() {
                        if !obj.is_empty() {
                            println!("\n=== Challenge Configs ===");
                            for (id, config) in obj {
                                println!("\nID: {}", id);
                                if let Some(name) = config.get("name") {
                                    println!("  Name: {}", name);
                                }
                                if let Some(image) = config.get("docker_image") {
                                    println!("  Docker: {}", image);
                                }
                                if let Some(mech) = config.get("mechanism_id") {
                                    println!("  Mechanism: {}", mech);
                                }
                            }
                        }
                    }
                }
            }
            return Ok(());
        }

        Commands::AddValidator { hotkey, stake } => {
            let hk = Hotkey::from_hex(&hotkey).ok_or_else(|| anyhow::anyhow!("Invalid hotkey"))?;
            let stake_raw = (stake * 1_000_000_000.0) as u64;
            let info = ValidatorInfo::new(hk, Stake::new(stake_raw));
            info!("Adding validator: {} with {} TAO", hotkey, stake);
            SudoAction::AddValidator { info }
        }

        Commands::RemoveValidator { hotkey } => {
            let hk = Hotkey::from_hex(&hotkey).ok_or_else(|| anyhow::anyhow!("Invalid hotkey"))?;
            info!("Removing validator: {}", hotkey);
            SudoAction::RemoveValidator { hotkey: hk }
        }

        Commands::UpdateConfig {
            min_stake,
            threshold,
            block_time,
        } => {
            let mut config = NetworkConfig::default();
            if let Some(s) = min_stake {
                config.min_stake = Stake::new((s * 1_000_000_000.0) as u64);
            }
            if let Some(t) = threshold {
                config.consensus_threshold = t;
            }
            if let Some(bt) = block_time {
                config.block_time_ms = bt;
            }
            info!("Updating network configuration");
            SudoAction::UpdateConfig { config }
        }

        Commands::Pause { reason } => {
            info!("Pausing network: {}", reason);
            SudoAction::EmergencyPause { reason }
        }

        Commands::Resume => {
            info!("Resuming network");
            SudoAction::Resume
        }

        Commands::Status => {
            let client = reqwest::Client::new();
            let rpc_url = format!("{}/rpc", args.rpc.trim_end_matches('/'));

            // Get system health
            println!("=== Network Status ===");
            println!("RPC: {}", args.rpc);

            let health_response = client
                .post(&rpc_url)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "system_health",
                    "params": [],
                    "id": 1
                }))
                .send()
                .await;

            match health_response {
                Ok(resp) => {
                    if let Ok(result) = resp.json::<serde_json::Value>().await {
                        if let Some(health) = result.get("result") {
                            println!("\nHealth:");
                            if let Some(peers) = health.get("peers") {
                                println!("  Peers: {}", peers);
                            }
                            if let Some(syncing) = health.get("isSyncing") {
                                println!("  Syncing: {}", syncing);
                            }
                            if let Some(block) = health.get("shouldHavePeers") {
                                println!("  Should have peers: {}", block);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to connect to RPC: {}", e);
                    return Ok(());
                }
            }

            // Get chain state
            let state_response = client
                .post(&rpc_url)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "chain_getState",
                    "params": [],
                    "id": 2
                }))
                .send()
                .await?;

            let state_result: serde_json::Value = state_response.json().await?;

            if let Some(state) = state_result.get("result") {
                println!("\nChain State:");
                if let Some(block) = state.get("block_height") {
                    println!("  Block Height: {}", block);
                }
                if let Some(epoch) = state.get("epoch") {
                    println!("  Epoch: {}", epoch);
                }
                if let Some(validators) = state.get("validators") {
                    if let Some(obj) = validators.as_object() {
                        println!("  Validators: {}", obj.len());
                    }
                }
                if let Some(challenges) = state.get("challenges") {
                    if let Some(obj) = challenges.as_object() {
                        println!("  Challenges: {}", obj.len());
                    }
                }
                if let Some(configs) = state.get("challenge_configs") {
                    if let Some(obj) = configs.as_object() {
                        println!("  Challenge Configs: {}", obj.len());
                    }
                }
            }

            return Ok(());
        }
    };

    // Create signed messages for the sudo action
    info!("Creating signed sudo action...");
    let proposal_id = consensus.propose_sudo(action).await?;
    info!("Proposal created: {:?}", proposal_id);

    // Collect all messages to broadcast
    let mut messages_to_send: Vec<SignedNetworkMessage> = Vec::new();
    while let Ok(msg) = msg_rx.try_recv() {
        messages_to_send.push(msg);
    }

    if messages_to_send.is_empty() {
        eprintln!("No messages generated - action may have failed");
        return Ok(());
    }

    // Submit each message via RPC
    info!(
        "Submitting {} messages via RPC to {}...",
        messages_to_send.len(),
        args.rpc
    );
    let client = reqwest::Client::new();

    for msg in &messages_to_send {
        let serialized = bincode::serialize(&msg)?;
        let hex_encoded = hex::encode(&serialized);

        let rpc_url = if args.rpc.ends_with("/rpc") {
            args.rpc.clone()
        } else {
            format!("{}/rpc", args.rpc.trim_end_matches('/'))
        };

        let response = client
            .post(&rpc_url)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "sudo_submit",
                "params": {
                    "signedMessage": hex_encoded
                },
                "id": 1
            }))
            .send()
            .await?;

        let result: serde_json::Value = response.json().await?;

        if let Some(error) = result.get("error") {
            eprintln!("RPC Error: {}", error);
            return Ok(());
        }

        if let Some(res) = result.get("result") {
            info!("Message submitted: {:?}", res);
        }
    }

    info!("Action submitted successfully via RPC!");
    Ok(())
}
