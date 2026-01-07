//! Challenge evaluator - generic proxy for routing requests to challenge containers
//!
//! IMPORTANT: This evaluator is challenge-agnostic. Each challenge defines its own
//! request/response format. The evaluator simply proxies JSON payloads.
//!
//! For term-challenge specific formats, see term-challenge-repo/src/server.rs

use crate::{ChallengeInstance, ContainerStatus};
use parking_lot::RwLock;
use platform_core::ChallengeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Generic evaluator for routing requests to challenge containers
pub struct ChallengeEvaluator {
    challenges: Arc<RwLock<HashMap<ChallengeId, ChallengeInstance>>>,
    client: reqwest::Client,
}

impl ChallengeEvaluator {
    pub fn new(challenges: Arc<RwLock<HashMap<ChallengeId, ChallengeInstance>>>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3600))
            .build()
            .expect("Failed to create HTTP client");

        Self { challenges, client }
    }

    /// Send a generic evaluation request to a challenge container
    /// The request/response format is defined by each challenge, not by the orchestrator
    pub async fn evaluate_generic(
        &self,
        challenge_id: ChallengeId,
        request: serde_json::Value,
        timeout_secs: Option<u64>,
    ) -> Result<serde_json::Value, EvaluatorError> {
        let instance = self
            .challenges
            .read()
            .get(&challenge_id)
            .cloned()
            .ok_or(EvaluatorError::ChallengeNotFound(challenge_id))?;

        if instance.status != ContainerStatus::Running {
            return Err(EvaluatorError::ChallengeNotReady(challenge_id));
        }

        let url = format!("{}/evaluate", instance.endpoint);

        debug!(
            challenge_id = %challenge_id,
            "Sending evaluation request to {}", url
        );

        let response = self
            .client
            .post(&url)
            .json(&request)
            .timeout(Duration::from_secs(timeout_secs.unwrap_or(3600)))
            .send()
            .await
            .map_err(|e| EvaluatorError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(EvaluatorError::ChallengeError {
                status: status.as_u16(),
                message: body,
            });
        }

        let result = response
            .json::<serde_json::Value>()
            .await
            .map_err(|e| EvaluatorError::ParseError(e.to_string()))?;

        info!(
            challenge_id = %challenge_id,
            "Evaluation completed"
        );

        Ok(result)
    }

    /// Proxy any request to a challenge endpoint
    pub async fn proxy_request(
        &self,
        challenge_id: ChallengeId,
        endpoint: &str,
        method: reqwest::Method,
        body: Option<serde_json::Value>,
        timeout_secs: Option<u64>,
    ) -> Result<serde_json::Value, EvaluatorError> {
        let instance = self
            .challenges
            .read()
            .get(&challenge_id)
            .cloned()
            .ok_or(EvaluatorError::ChallengeNotFound(challenge_id))?;

        if instance.status != ContainerStatus::Running {
            return Err(EvaluatorError::ChallengeNotReady(challenge_id));
        }

        let url = format!("{}/{}", instance.endpoint, endpoint.trim_start_matches('/'));

        debug!(
            challenge_id = %challenge_id,
            method = %method,
            "Proxying request to {}", url
        );

        let mut req = self
            .client
            .request(method, &url)
            .timeout(Duration::from_secs(timeout_secs.unwrap_or(30)));

        if let Some(b) = body {
            req = req.json(&b);
        }

        let response = req
            .send()
            .await
            .map_err(|e| EvaluatorError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(EvaluatorError::ChallengeError {
                status: status.as_u16(),
                message: body,
            });
        }

        response
            .json()
            .await
            .map_err(|e| EvaluatorError::ParseError(e.to_string()))
    }

    /// Get challenge info
    pub async fn get_info(
        &self,
        challenge_id: ChallengeId,
    ) -> Result<ChallengeInfo, EvaluatorError> {
        let instance = self
            .challenges
            .read()
            .get(&challenge_id)
            .cloned()
            .ok_or(EvaluatorError::ChallengeNotFound(challenge_id))?;

        let url = format!("{}/info", instance.endpoint);

        let response = self
            .client
            .get(&url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| EvaluatorError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(EvaluatorError::ChallengeError {
                status: response.status().as_u16(),
                message: "Failed to get challenge info".to_string(),
            });
        }

        response
            .json()
            .await
            .map_err(|e| EvaluatorError::ParseError(e.to_string()))
    }

    /// Check health of a specific challenge
    pub async fn check_health(&self, challenge_id: ChallengeId) -> Result<bool, EvaluatorError> {
        let instance = self
            .challenges
            .read()
            .get(&challenge_id)
            .cloned()
            .ok_or(EvaluatorError::ChallengeNotFound(challenge_id))?;

        let url = format!("{}/health", instance.endpoint);

        match self
            .client
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(e) => {
                warn!(challenge_id = %challenge_id, "Health check failed: {}", e);
                Ok(false)
            }
        }
    }

    /// List all available challenges with their status
    pub fn list_challenges(&self) -> Vec<ChallengeStatus> {
        self.challenges
            .read()
            .iter()
            .map(|(id, instance)| ChallengeStatus {
                challenge_id: *id,
                image: instance.image.clone(),
                status: instance.status.clone(),
                endpoint: instance.endpoint.clone(),
                started_at: instance.started_at,
            })
            .collect()
    }
}

/// Challenge info response (generic)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeInfo {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub mechanism_id: u8,
    #[serde(default)]
    pub emission_weight: f64,
    #[serde(default)]
    pub tasks_count: u32,
    pub description: Option<String>,
}

/// Challenge status for listing
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeStatus {
    pub challenge_id: ChallengeId,
    pub image: String,
    pub status: ContainerStatus,
    pub endpoint: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
}

/// Evaluator errors
#[derive(Debug, thiserror::Error)]
pub enum EvaluatorError {
    #[error("Challenge not found: {0}")]
    ChallengeNotFound(ChallengeId),

    #[error("Challenge not ready: {0}")]
    ChallengeNotReady(ChallengeId),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Challenge error (status {status}): {message}")]
    ChallengeError { status: u16, message: String },

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Timeout")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::RwLock;
    use platform_core::ChallengeId;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio_test::block_on;

    fn sample_instance(status: ContainerStatus) -> ChallengeInstance {
        ChallengeInstance {
            challenge_id: ChallengeId::new(),
            container_id: "cid".into(),
            image: "ghcr.io/platformnetwork/example:latest".into(),
            endpoint: "http://127.0.0.1:9000".into(),
            started_at: chrono::Utc::now(),
            status,
        }
    }

    #[test]
    fn test_challenge_info_deserialize() {
        let json = r#"{
            "name": "term-challenge",
            "version": "1.0.0",
            "description": "Terminal benchmark challenge"
        }"#;

        let info: ChallengeInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.name, "term-challenge");
        assert_eq!(info.mechanism_id, 0); // default
    }

    #[test]
    fn test_evaluate_generic_requires_running_status() {
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let instance = sample_instance(ContainerStatus::Starting);
        let challenge_id = instance.challenge_id;
        challenges.write().insert(challenge_id, instance.clone());

        let evaluator = ChallengeEvaluator::new(challenges);
        let err = block_on(evaluator.evaluate_generic(challenge_id, serde_json::json!({}), None))
            .expect_err("should fail when not running");

        match err {
            EvaluatorError::ChallengeNotReady(id) => assert_eq!(id, challenge_id),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_proxy_request_missing_challenge() {
        let evaluator = ChallengeEvaluator::new(Arc::new(RwLock::new(HashMap::new())));
        let challenge_id = ChallengeId::new();
        let err = block_on(evaluator.proxy_request(
            challenge_id,
            "status",
            reqwest::Method::GET,
            None,
            None,
        ))
        .expect_err("missing challenge should error");

        match err {
            EvaluatorError::ChallengeNotFound(id) => assert_eq!(id, challenge_id),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_list_challenges_returns_current_instances() {
        let challenges = Arc::new(RwLock::new(HashMap::new()));
        let instance_a = sample_instance(ContainerStatus::Running);
        let instance_b = sample_instance(ContainerStatus::Unhealthy);
        let id_a = instance_a.challenge_id;
        let id_b = instance_b.challenge_id;
        challenges.write().insert(id_a, instance_a.clone());
        challenges.write().insert(id_b, instance_b.clone());

        let evaluator = ChallengeEvaluator::new(challenges);
        let list = evaluator.list_challenges();
        assert_eq!(list.len(), 2);

        let status_map: std::collections::HashMap<ChallengeId, ContainerStatus> = list
            .into_iter()
            .map(|entry| (entry.challenge_id, entry.status))
            .collect();

        assert_eq!(status_map.get(&id_a), Some(&ContainerStatus::Running));
        assert_eq!(status_map.get(&id_b), Some(&ContainerStatus::Unhealthy));
    }
}
