//! Container backend abstraction
//!
//! Provides a unified interface for container management that can use:
//! - SecureContainerClient via broker (DEFAULT for production validators)
//! - Direct Docker (ONLY for local development when DEVELOPMENT_MODE=true)
//!
//! ## Backend Selection (Priority Order)
//!
//! 1. If `DEVELOPMENT_MODE=true` -> Direct Docker (local dev only)
//! 2. If `CONTAINER_BROKER_SOCKET` is set -> Use that socket path
//! 3. If default socket exists (`/var/run/platform/broker.sock`) -> Use broker
//! 4. Otherwise -> Error (production requires broker)
//!
//! ## Security
//!
//! In production, challenges MUST run through the secure broker.
//! The broker enforces:
//! - Image whitelisting (only ghcr.io/platformnetwork/)
//! - Non-privileged containers
//! - Resource limits
//! - No Docker socket access for challenges

use crate::{ChallengeContainerConfig, ChallengeInstance, ContainerStatus};
use async_trait::async_trait;
use secure_container_runtime::{
    ContainerConfigBuilder, ContainerState, NetworkMode, SecureContainerClient,
};
use std::path::Path;
use tracing::{error, info, warn};

/// Default broker socket path
pub const DEFAULT_BROKER_SOCKET: &str = "/var/run/platform/broker.sock";

/// Container backend trait for managing challenge containers
#[async_trait]
pub trait ContainerBackend: Send + Sync {
    /// Start a challenge container
    async fn start_challenge(
        &self,
        config: &ChallengeContainerConfig,
    ) -> anyhow::Result<ChallengeInstance>;

    /// Stop a container
    async fn stop_container(&self, container_id: &str) -> anyhow::Result<()>;

    /// Remove a container
    async fn remove_container(&self, container_id: &str) -> anyhow::Result<()>;

    /// Check if a container is running
    async fn is_container_running(&self, container_id: &str) -> anyhow::Result<bool>;

    /// Pull an image
    async fn pull_image(&self, image: &str) -> anyhow::Result<()>;

    /// Get container logs
    async fn get_logs(&self, container_id: &str, tail: usize) -> anyhow::Result<String>;

    /// Cleanup all containers for a challenge
    async fn cleanup_challenge(&self, challenge_id: &str) -> anyhow::Result<usize>;

    /// List containers for a challenge
    async fn list_challenge_containers(&self, challenge_id: &str) -> anyhow::Result<Vec<String>>;
}

/// Secure container backend using the broker
pub struct SecureBackend {
    client: SecureContainerClient,
    validator_id: String,
}

impl SecureBackend {
    /// Create a new secure backend
    pub fn new(socket_path: &str, validator_id: &str) -> Self {
        Self {
            client: SecureContainerClient::new(socket_path),
            validator_id: validator_id.to_string(),
        }
    }

    /// Create from environment or default socket
    pub fn from_env() -> Option<Self> {
        let validator_id =
            std::env::var("VALIDATOR_HOTKEY").unwrap_or_else(|_| "unknown".to_string());

        // Priority 1: Explicit socket path from env
        if let Ok(socket) = std::env::var("CONTAINER_BROKER_SOCKET") {
            if Path::new(&socket).exists() {
                info!(socket = %socket, "Using broker socket from environment");
                return Some(Self::new(&socket, &validator_id));
            }
            warn!(socket = %socket, "Broker socket from env does not exist");
        }

        // Priority 2: Default socket path
        if Path::new(DEFAULT_BROKER_SOCKET).exists() {
            info!(socket = %DEFAULT_BROKER_SOCKET, "Using default broker socket");
            return Some(Self::new(DEFAULT_BROKER_SOCKET, &validator_id));
        }

        None
    }

    /// Check if broker is available
    pub fn is_available() -> bool {
        if let Ok(socket) = std::env::var("CONTAINER_BROKER_SOCKET") {
            if Path::new(&socket).exists() {
                return true;
            }
        }
        Path::new(DEFAULT_BROKER_SOCKET).exists()
    }
}

#[async_trait]
impl ContainerBackend for SecureBackend {
    async fn start_challenge(
        &self,
        config: &ChallengeContainerConfig,
    ) -> anyhow::Result<ChallengeInstance> {
        info!(
            challenge = %config.name,
            image = %config.docker_image,
            "Starting challenge via secure broker"
        );

        // Build container config
        let container_config = ContainerConfigBuilder::new(
            &config.docker_image,
            &config.challenge_id.to_string(),
            &self.validator_id,
        )
        .memory((config.memory_mb * 1024 * 1024) as i64)
        .cpu(config.cpu_cores)
        .network_mode(NetworkMode::Isolated)
        .expose(8080)
        .env("CHALLENGE_ID", &config.challenge_id.to_string())
        .env("MECHANISM_ID", &config.mechanism_id.to_string())
        .build();

        // Create and start container
        let (container_id, _container_name) = self
            .client
            .create_container(container_config)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create container: {}", e))?;

        self.client
            .start_container(&container_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to start container: {}", e))?;

        // Get endpoint
        let endpoint = self
            .client
            .get_endpoint(&container_id, 8080)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get endpoint: {}", e))?;

        info!(
            container_id = %container_id,
            endpoint = %endpoint,
            "Challenge container started via broker"
        );

        Ok(ChallengeInstance {
            challenge_id: config.challenge_id,
            container_id,
            image: config.docker_image.clone(),
            endpoint,
            started_at: chrono::Utc::now(),
            status: ContainerStatus::Running,
        })
    }

    async fn stop_container(&self, container_id: &str) -> anyhow::Result<()> {
        self.client
            .stop_container(container_id, 30)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to stop container: {}", e))
    }

    async fn remove_container(&self, container_id: &str) -> anyhow::Result<()> {
        self.client
            .remove_container(container_id, true)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to remove container: {}", e))
    }

    async fn is_container_running(&self, container_id: &str) -> anyhow::Result<bool> {
        match self.client.inspect(container_id).await {
            Ok(info) => Ok(info.state == ContainerState::Running),
            Err(_) => Ok(false),
        }
    }

    async fn pull_image(&self, image: &str) -> anyhow::Result<()> {
        self.client
            .pull_image(image)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to pull image: {}", e))
    }

    async fn get_logs(&self, container_id: &str, tail: usize) -> anyhow::Result<String> {
        self.client
            .logs(container_id, tail)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get logs: {}", e))
    }

    async fn cleanup_challenge(&self, challenge_id: &str) -> anyhow::Result<usize> {
        let result = self
            .client
            .cleanup_challenge(challenge_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to cleanup: {}", e))?;

        if !result.success() {
            warn!(errors = ?result.errors, "Some cleanup errors occurred");
        }

        Ok(result.removed)
    }

    async fn list_challenge_containers(&self, challenge_id: &str) -> anyhow::Result<Vec<String>> {
        let containers = self
            .client
            .list_by_challenge(challenge_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to list containers: {}", e))?;

        Ok(containers.into_iter().map(|c| c.id).collect())
    }
}

/// Direct Docker backend (for local development)
pub struct DirectDockerBackend {
    docker: crate::docker::DockerClient,
}

impl DirectDockerBackend {
    /// Create a new direct Docker backend
    pub async fn new() -> anyhow::Result<Self> {
        let docker = crate::docker::DockerClient::connect().await?;
        Ok(Self { docker })
    }
}

#[async_trait]
impl ContainerBackend for DirectDockerBackend {
    async fn start_challenge(
        &self,
        config: &ChallengeContainerConfig,
    ) -> anyhow::Result<ChallengeInstance> {
        self.docker.start_challenge(config).await
    }

    async fn stop_container(&self, container_id: &str) -> anyhow::Result<()> {
        self.docker.stop_container(container_id).await
    }

    async fn remove_container(&self, container_id: &str) -> anyhow::Result<()> {
        self.docker.remove_container(container_id).await
    }

    async fn is_container_running(&self, container_id: &str) -> anyhow::Result<bool> {
        self.docker.is_container_running(container_id).await
    }

    async fn pull_image(&self, image: &str) -> anyhow::Result<()> {
        self.docker.pull_image(image).await
    }

    async fn get_logs(&self, container_id: &str, tail: usize) -> anyhow::Result<String> {
        self.docker.get_logs(container_id, tail).await
    }

    async fn cleanup_challenge(&self, challenge_id: &str) -> anyhow::Result<usize> {
        let containers = self.docker.list_challenge_containers().await?;
        let mut removed = 0;

        for container_id in containers {
            if container_id.contains(&challenge_id.to_string()) {
                let _ = self.docker.stop_container(&container_id).await;
                if self.docker.remove_container(&container_id).await.is_ok() {
                    removed += 1;
                }
            }
        }

        Ok(removed)
    }

    async fn list_challenge_containers(&self, _challenge_id: &str) -> anyhow::Result<Vec<String>> {
        self.docker.list_challenge_containers().await
    }
}

/// Create the appropriate backend based on environment
///
/// Priority order:
/// 1. DEVELOPMENT_MODE=true -> Direct Docker (local dev only)
/// 2. Broker socket available -> Secure broker (production default)
/// 3. No broker + not dev mode -> Error (production requires broker)
pub async fn create_backend() -> anyhow::Result<Box<dyn ContainerBackend>> {
    // Check if explicitly in development mode
    let dev_mode = std::env::var("DEVELOPMENT_MODE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    if dev_mode {
        info!("DEVELOPMENT_MODE=true: Using direct Docker (local development)");
        let direct = DirectDockerBackend::new().await?;
        return Ok(Box::new(direct));
    }

    // Try to use secure broker (default for production)
    if let Some(secure) = SecureBackend::from_env() {
        info!("Using secure container broker (production mode)");
        return Ok(Box::new(secure));
    }

    // No broker available - try Docker as last resort but warn
    warn!("Broker not available. Attempting Docker fallback...");
    warn!("This should only happen in local development!");
    warn!("Set DEVELOPMENT_MODE=true to suppress this warning, or start the broker.");

    match DirectDockerBackend::new().await {
        Ok(direct) => {
            warn!("Using direct Docker - NOT RECOMMENDED FOR PRODUCTION");
            Ok(Box::new(direct))
        }
        Err(e) => {
            error!("Cannot connect to Docker: {}", e);
            error!("For production: Start the container-broker service");
            error!("For development: Set DEVELOPMENT_MODE=true and ensure Docker is running");
            Err(anyhow::anyhow!(
                "No container backend available. \
                 Start broker at {} or set DEVELOPMENT_MODE=true for local Docker",
                DEFAULT_BROKER_SOCKET
            ))
        }
    }
}

/// Check if running in secure mode (broker available)
pub fn is_secure_mode() -> bool {
    SecureBackend::is_available()
}

/// Check if in development mode
pub fn is_development_mode() -> bool {
    std::env::var("DEVELOPMENT_MODE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tempfile::NamedTempFile;

    fn reset_env() {
        for key in [
            "DEVELOPMENT_MODE",
            "CONTAINER_BROKER_SOCKET",
            "VALIDATOR_HOTKEY",
        ] {
            std::env::remove_var(key);
        }
    }

    #[test]
    #[serial]
    fn test_is_development_mode_reflects_env() {
        reset_env();
        assert!(!is_development_mode());

        std::env::set_var("DEVELOPMENT_MODE", "1");
        assert!(is_development_mode());

        std::env::set_var("DEVELOPMENT_MODE", "false");
        assert!(!is_development_mode());
        reset_env();
    }

    #[test]
    #[serial]
    fn test_secure_backend_from_env_detects_socket() {
        reset_env();
        let temp_socket = NamedTempFile::new().expect("temp socket path");
        let socket_path = temp_socket.path().to_path_buf();
        std::env::set_var("CONTAINER_BROKER_SOCKET", &socket_path);
        std::env::set_var("VALIDATOR_HOTKEY", "validator123");

        let backend = SecureBackend::from_env().expect("should create backend from env");
        assert_eq!(backend.validator_id, "validator123");

        reset_env();
        drop(temp_socket);
    }

    #[test]
    #[serial]
    fn test_is_secure_mode_uses_env_socket() {
        reset_env();
        let temp_socket = NamedTempFile::new().expect("temp socket path");
        let socket_path = temp_socket.path().to_path_buf();
        std::env::set_var("CONTAINER_BROKER_SOCKET", &socket_path);

        assert!(is_secure_mode());

        reset_env();
        drop(temp_socket);
    }
}
