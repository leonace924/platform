#![allow(dead_code, unused_variables, unused_imports)]
//! Platform Challenge SDK
//!
//! SDK for developing challenges on Platform Network.
//! Supports two modes:
//! 1. **Server Mode** - Challenge runs as HTTP server, platform calls `/evaluate`
//! 2. **Client Mode** - Challenge connects via WebSocket to platform
//!
//! # Quick Start - Server Mode
//!
//! ```rust,ignore
//! use platform_challenge_sdk::prelude::*;
//!
//! struct MyChallenge;
//!
//! #[async_trait]
//! impl ServerChallenge for MyChallenge {
//!     fn challenge_id(&self) -> &str { "my-challenge" }
//!     fn name(&self) -> &str { "My Challenge" }
//!     fn version(&self) -> &str { "0.1.0" }
//!
//!     async fn evaluate(&self, req: EvaluationRequest) -> Result<EvaluationResponse, ChallengeError> {
//!         // Your evaluation logic here
//!         let score = evaluate_submission(&req.data)?;
//!         Ok(EvaluationResponse::success(&req.request_id, score, json!({})))
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), ChallengeError> {
//!     ChallengeServer::builder(MyChallenge)
//!         .port(8080)
//!         .build()
//!         .run()
//!         .await
//! }
//! ```
//!
//! # Quick Start - Client Mode
//!
//! ```rust,ignore
//! use platform_challenge_sdk::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), ChallengeError> {
//!     run_as_client(MyChallenge).await
//! }
//! ```
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     Your Challenge                          │
//! │  impl ServerChallenge { evaluate(), validate(), ... }       │
//! ├─────────────────────────────────────────────────────────────┤
//! │                  Platform Challenge SDK                     │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
//! │  │   Server    │  │   Client    │  │   Types     │        │
//! │  │ (HTTP mode) │  │ (WS mode)   │  │ (generic)   │        │
//! │  └─────────────┘  └─────────────┘  └─────────────┘        │
//! ├─────────────────────────────────────────────────────────────┤
//! │                    Platform Server                          │
//! │         (orchestration, auth, consensus)                    │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Note on Terminology
//!
//! This SDK is **generic** - it doesn't use challenge-specific terms like
//! "agent", "miner", etc. Each challenge defines its own terminology:
//! - `EvaluationRequest.data` contains challenge-specific submission data
//! - `EvaluationResponse.results` contains challenge-specific result data
//! - `participant_id` is generic (could be miner hotkey, user id, etc.)

// ============================================================================
// NEW CENTRALIZED API MODULES (use these for new challenges)
// ============================================================================

/// Client mode - connect to platform via WebSocket
pub mod platform_client;
/// Server mode - expose challenge as HTTP server
pub mod server;

// ============================================================================
// LEGACY P2P MODULES (deprecated, kept for compatibility)
// ============================================================================

#[deprecated(since = "0.2.0", note = "Use server module for new challenges")]
pub mod challenge;
#[deprecated(since = "0.2.0", note = "Use server module for new challenges")]
pub mod context;
pub mod data;
pub mod database;
#[deprecated(since = "0.2.0", note = "P2P storage replaced by central API")]
pub mod distributed_storage;
pub mod error;
#[deprecated(since = "0.2.0", note = "P2P replaced by central API")]
pub mod p2p;
#[deprecated(since = "0.2.0", note = "P2P storage replaced by central API")]
pub mod p2p_chain_storage;
pub mod routes;
#[deprecated(since = "0.2.0", note = "Storage handled by platform-server")]
pub mod storage_client;
#[deprecated(since = "0.2.0", note = "Storage handled by platform-server")]
pub mod storage_schema;
pub mod submission_types;
pub mod test_challenge;
pub mod types;
pub mod weight_types;
pub mod weights;

// ============================================================================
// NEW API EXPORTS
// ============================================================================

pub use platform_client::{
    run_as_client, ChallengeMessage, ConnectionState, PlatformClient, PlatformClientConfig,
    ServerMessage,
};
pub use server::{
    ChallengeServer, ChallengeServerBuilder, ConfigLimits, ConfigResponse, EvaluationRequest,
    EvaluationResponse, HealthResponse, ServerChallenge, ServerConfig, ValidationRequest,
    ValidationResponse,
};

// ============================================================================
// LEGACY EXPORTS (deprecated)
// ============================================================================

#[allow(deprecated)]
pub use challenge::*;
#[allow(deprecated)]
pub use context::*;
pub use data::*;
pub use database::*;
#[allow(deprecated)]
pub use distributed_storage::*;
pub use error::*;
#[allow(deprecated)]
pub use p2p::*;
#[allow(deprecated)]
pub use p2p_chain_storage::*;
pub use routes::*;
pub use submission_types::*;
pub use test_challenge::SimpleTestChallenge;
pub use types::*;
pub use weight_types::*;
pub use weights::*;

/// Prelude for new centralized API
pub mod prelude {
    // New API
    pub use super::error::ChallengeError;
    pub use super::platform_client::{run_as_client, PlatformClient, PlatformClientConfig};
    pub use super::server::{
        ChallengeServer, EvaluationRequest, EvaluationResponse, ServerChallenge, ServerConfig,
        ValidationRequest, ValidationResponse,
    };

    // Common utilities
    pub use async_trait::async_trait;
    pub use serde::{Deserialize, Serialize};
    pub use serde_json::{json, Value};
    pub use tracing::{debug, error, info, warn};
}

/// Legacy prelude (deprecated, use prelude instead)
#[deprecated(since = "0.2.0", note = "Use prelude module instead")]
pub mod legacy_prelude {
    #[allow(deprecated)]
    pub use super::challenge::Challenge;
    #[allow(deprecated)]
    pub use super::context::ChallengeContext;
    #[allow(deprecated)]
    pub use super::p2p::*;
    pub use super::routes::*;
    pub use super::submission_types::*;
    pub use super::types::*;
    pub use super::weight_types::*;
    pub use super::weights::*;
    pub use async_trait::async_trait;
    pub use serde_json::Value;
}
