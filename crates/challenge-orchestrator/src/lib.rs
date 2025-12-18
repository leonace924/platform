//! Challenge Orchestrator
//!
//! Manages Docker containers for challenges. Provides:
//! - Container lifecycle (start, stop, update)
//! - Health monitoring
//! - Evaluation routing
//! - Hot-swap without core restart

pub mod config;
pub mod docker;
pub mod evaluator;
pub mod health;
pub mod lifecycle;

pub use config::*;
pub use docker::*;
pub use evaluator::*;
pub use health::*;
pub use lifecycle::*;

use parking_lot::RwLock;
use platform_core::ChallengeId;
use std::collections::HashMap;
use std::sync::Arc;

/// Main orchestrator managing all challenge containers
#[allow(dead_code)]
pub struct ChallengeOrchestrator {
    docker: DockerClient,
    challenges: Arc<RwLock<HashMap<ChallengeId, ChallengeInstance>>>,
    health_monitor: HealthMonitor,
    config: OrchestratorConfig,
}

/// Default network name for Platform containers
pub const PLATFORM_NETWORK: &str = "platform-network";

impl ChallengeOrchestrator {
    pub async fn new(config: OrchestratorConfig) -> anyhow::Result<Self> {
        let docker = DockerClient::connect_with_network(PLATFORM_NETWORK).await?;

        // Ensure the Docker network exists
        docker.ensure_network().await?;

        // Try to connect the current container to the network (if running in Docker)
        if let Err(e) = docker.connect_self_to_network().await {
            tracing::debug!("Could not connect to network (may not be in Docker): {}", e);
        }

        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let health_monitor = HealthMonitor::new(challenges.clone(), config.health_check_interval);

        Ok(Self {
            docker,
            challenges,
            health_monitor,
            config,
        })
    }

    /// Start the orchestrator (health monitoring loop)
    pub async fn start(&self) -> anyhow::Result<()> {
        self.health_monitor.start().await
    }

    /// Add and start a new challenge
    pub async fn add_challenge(&self, config: ChallengeContainerConfig) -> anyhow::Result<()> {
        let instance = self.docker.start_challenge(&config).await?;
        self.challenges
            .write()
            .insert(config.challenge_id, instance);
        tracing::info!(challenge_id = %config.challenge_id, "Challenge container started");
        Ok(())
    }

    /// Update a challenge (pull new image, restart container)
    pub async fn update_challenge(&self, config: ChallengeContainerConfig) -> anyhow::Result<()> {
        // Stop old container if exists - get container_id first to avoid holding lock across await
        let old_container_id = {
            self.challenges
                .read()
                .get(&config.challenge_id)
                .map(|i| i.container_id.clone())
        };
        if let Some(container_id) = old_container_id {
            self.docker.stop_container(&container_id).await?;
        }

        // Pull new image and start
        self.docker.pull_image(&config.docker_image).await?;
        let instance = self.docker.start_challenge(&config).await?;
        self.challenges
            .write()
            .insert(config.challenge_id, instance);

        tracing::info!(
            challenge_id = %config.challenge_id,
            image = %config.docker_image,
            "Challenge container updated"
        );
        Ok(())
    }

    /// Remove a challenge
    pub async fn remove_challenge(&self, challenge_id: ChallengeId) -> anyhow::Result<()> {
        // Get container_id and remove from map first to avoid holding lock across await
        let container_id = self
            .challenges
            .write()
            .remove(&challenge_id)
            .map(|i| i.container_id);
        if let Some(container_id) = container_id {
            self.docker.stop_container(&container_id).await?;
            self.docker.remove_container(&container_id).await?;
            tracing::info!(challenge_id = %challenge_id, "Challenge container removed");
        }
        Ok(())
    }

    /// Get evaluator for running evaluations
    pub fn evaluator(&self) -> ChallengeEvaluator {
        ChallengeEvaluator::new(self.challenges.clone())
    }

    /// List active challenges
    pub fn list_challenges(&self) -> Vec<ChallengeId> {
        self.challenges.read().keys().cloned().collect()
    }

    /// Get challenge instance info
    pub fn get_challenge(&self, id: &ChallengeId) -> Option<ChallengeInstance> {
        self.challenges.read().get(id).cloned()
    }

    /// Sync challenges with network state
    pub async fn sync_challenges(
        &self,
        configs: &[ChallengeContainerConfig],
    ) -> anyhow::Result<()> {
        let current_ids: std::collections::HashSet<_> =
            self.challenges.read().keys().cloned().collect();
        let target_ids: std::collections::HashSet<_> =
            configs.iter().map(|c| c.challenge_id).collect();

        // Remove challenges not in target
        for id in current_ids.difference(&target_ids) {
            self.remove_challenge(*id).await?;
        }

        // Add/update challenges
        for config in configs {
            let needs_update = self
                .challenges
                .read()
                .get(&config.challenge_id)
                .map(|i| i.image != config.docker_image)
                .unwrap_or(true);

            if needs_update {
                self.update_challenge(config.clone()).await?;
            }
        }

        Ok(())
    }
}

/// Running challenge instance
#[derive(Clone, Debug)]
pub struct ChallengeInstance {
    pub challenge_id: ChallengeId,
    pub container_id: String,
    pub image: String,
    pub endpoint: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub status: ContainerStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ContainerStatus {
    Starting,
    Running,
    Unhealthy,
    Stopped,
}
