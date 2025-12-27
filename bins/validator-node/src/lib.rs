//! Validator Node Library
//!
//! This library exposes the validator node configuration for the unified platform binary.
//! The actual implementation is in main.rs which can be run as a standalone binary.
//!
//! Note: Full refactoring to expose run() would require moving ~4000 lines of code
//! from main.rs to lib.rs. For now, the unified binary delegates to validator-node.

use std::path::PathBuf;

/// Validator CLI arguments (matches main.rs Args)
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    pub secret_key: String,
    pub listen: String,
    pub bootstrap: Option<String>,
    pub data_dir: PathBuf,
    pub sudo_key: Option<String>,
    pub stake: f64,
    pub min_stake: f64,
    pub subtensor_endpoint: String,
    pub netuid: u16,
    pub no_bittensor: bool,
    pub epoch_length: u64,
    pub rpc_port: u16,
    pub platform_server: Option<String>,
    pub broker_port: u16,
}
