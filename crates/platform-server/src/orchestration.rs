//! Challenge Orchestration - Dynamic container management
//!
//! Manages challenge containers automatically:
//! - Loads challenges from database
//! - Pulls Docker images
//! - Starts/stops containers
//! - Health monitoring
//! - Dynamic routing

use crate::db::{queries, DbPool};
use crate::models::RegisteredChallenge;
use anyhow::{anyhow, Result};
use challenge_orchestrator::{
    ChallengeInstance, ChallengeOrchestrator, ContainerStatus, OrchestratorConfig,
};
use parking_lot::RwLock;
use platform_core::{ChallengeContainerConfig, ChallengeId};
use reqwest::Client;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

/// Server-side challenge manager
/// Integrates challenge-orchestrator with database-backed configuration
pub struct ChallengeManager {
    orchestrator: ChallengeOrchestrator,
    db: DbPool,
    /// Maps challenge string ID to endpoint URL
    endpoints: Arc<RwLock<HashMap<String, String>>>,
    /// Maps challenge string ID to ChallengeId (UUID)
    id_map: Arc<RwLock<HashMap<String, ChallengeId>>>,
    http_client: Client,
}

impl ChallengeManager {
    pub async fn new(db: DbPool) -> Result<Self> {
        let config = OrchestratorConfig::default();
        let orchestrator = ChallengeOrchestrator::new(config).await?;

        let http_client = Client::builder()
            .timeout(Duration::from_secs(600))
            .build()?;

        Ok(Self {
            orchestrator,
            db,
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            id_map: Arc::new(RwLock::new(HashMap::new())),
            http_client,
        })
    }

    /// Load challenges from database and start containers
    pub async fn start_all(&self) -> Result<()> {
        let challenges = queries::get_active_challenges(&self.db).await?;

        if challenges.is_empty() {
            info!("No registered challenges found in database");
            return Ok(());
        }

        info!("Starting {} challenges from database...", challenges.len());

        for challenge in challenges {
            match self.start_challenge(&challenge).await {
                Ok(endpoint) => {
                    info!("  ✓ {} ({}) -> {}", challenge.name, challenge.id, endpoint);
                }
                Err(e) => {
                    error!("  ✗ {} failed to start: {}", challenge.name, e);
                }
            }
        }

        Ok(())
    }

    /// Start a single challenge container
    pub async fn start_challenge(&self, challenge: &RegisteredChallenge) -> Result<String> {
        // Create a deterministic ChallengeId from the string ID
        let challenge_id = ChallengeId::from_string(&challenge.id);

        let config = ChallengeContainerConfig {
            challenge_id,
            name: challenge.name.clone(),
            docker_image: challenge.docker_image.clone(),
            mechanism_id: challenge.mechanism_id,
            emission_weight: challenge.emission_weight,
            timeout_secs: challenge.timeout_secs,
            cpu_cores: challenge.cpu_cores,
            memory_mb: challenge.memory_mb,
            gpu_required: challenge.gpu_required,
        };

        // Start via orchestrator
        self.orchestrator.add_challenge(config).await?;

        // Get instance info
        let instance = self
            .orchestrator
            .get_challenge(&challenge_id)
            .ok_or_else(|| anyhow!("Challenge not found after start"))?;

        let endpoint = instance.endpoint.clone();

        // Update database
        queries::update_challenge_container(
            &self.db,
            &challenge.id,
            Some(&endpoint),
            Some(&instance.container_id),
            true,
        )
        .await?;

        // Store mappings for routing
        self.endpoints
            .write()
            .insert(challenge.id.clone(), endpoint.clone());
        self.id_map
            .write()
            .insert(challenge.id.clone(), challenge_id);

        Ok(endpoint)
    }

    /// Stop a challenge container
    pub async fn stop_challenge(&self, challenge_id: &str) -> Result<()> {
        // Get the ChallengeId from our mapping
        let id = self
            .id_map
            .read()
            .get(challenge_id)
            .cloned()
            .ok_or_else(|| anyhow!("Challenge {} not found", challenge_id))?;

        self.orchestrator.remove_challenge(id).await?;

        // Update database
        queries::update_challenge_container(&self.db, challenge_id, None, None, false).await?;

        // Remove from routing
        self.endpoints.write().remove(challenge_id);
        self.id_map.write().remove(challenge_id);

        Ok(())
    }

    /// Get endpoint for a challenge
    pub fn get_endpoint(&self, challenge_id: &str) -> Option<String> {
        self.endpoints.read().get(challenge_id).cloned()
    }

    /// Get all active endpoints
    pub fn get_all_endpoints(&self) -> HashMap<String, String> {
        self.endpoints.read().clone()
    }

    /// Check health of all challenges
    pub async fn health_check_all(&self) -> Vec<(String, bool)> {
        let endpoints = self.get_all_endpoints();
        let mut results = Vec::new();

        for (id, endpoint) in endpoints {
            let healthy = self.check_health(&endpoint).await;
            results.push((id.clone(), healthy));

            // Update database
            let _ =
                queries::update_challenge_container(&self.db, &id, Some(&endpoint), None, healthy)
                    .await;
        }

        results
    }

    async fn check_health(&self, endpoint: &str) -> bool {
        let url = format!("{}/health", endpoint);
        match self.http_client.get(&url).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    /// List all active challenge IDs
    pub fn list_challenge_ids(&self) -> Vec<String> {
        self.endpoints.read().keys().cloned().collect()
    }
}
