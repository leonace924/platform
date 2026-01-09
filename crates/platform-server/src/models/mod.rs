//! Data models for Platform Server

use serde::{Deserialize, Serialize};

// ============================================================================
// VALIDATOR
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub hotkey: String,
    pub stake: u64,
    pub last_seen: Option<i64>,
    pub is_active: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorRegistration {
    pub hotkey: String,
    pub stake: u64,
    pub signature: String,
    pub timestamp: i64,
}

// ============================================================================
// SUBMISSION
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Submission {
    pub id: String,
    pub agent_hash: String,
    pub miner_hotkey: String,
    pub source_code: Option<String>,
    pub source_hash: String,
    pub name: Option<String>,
    pub version: String,
    pub epoch: u64,
    pub status: SubmissionStatus,
    /// API key for LLM inferences (stored securely)
    pub api_key: Option<String>,
    /// API provider (openrouter, chutes, openai, anthropic, grok)
    pub api_provider: Option<String>,
    /// Total cost accumulated for this submission (USD)
    pub total_cost_usd: Option<f64>,
    /// Deprecated: use api_key instead
    pub api_keys_encrypted: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionStatus {
    Pending,
    Evaluating,
    Completed,
    Failed,
    Rejected,
}

impl ToString for SubmissionStatus {
    fn to_string(&self) -> String {
        match self {
            SubmissionStatus::Pending => "pending".to_string(),
            SubmissionStatus::Evaluating => "evaluating".to_string(),
            SubmissionStatus::Completed => "completed".to_string(),
            SubmissionStatus::Failed => "failed".to_string(),
            SubmissionStatus::Rejected => "rejected".to_string(),
        }
    }
}

impl From<&str> for SubmissionStatus {
    fn from(s: &str) -> Self {
        match s {
            "pending" => SubmissionStatus::Pending,
            "evaluating" => SubmissionStatus::Evaluating,
            "completed" => SubmissionStatus::Completed,
            "failed" => SubmissionStatus::Failed,
            "rejected" => SubmissionStatus::Rejected,
            _ => SubmissionStatus::Pending,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitAgentRequest {
    pub source_code: String,
    pub miner_hotkey: String,
    pub signature: String,
    pub name: Option<String>,
    /// API key for LLM inferences (plaintext - server handles securely)
    pub api_key: Option<String>,
    /// API provider: openrouter, chutes, openai, anthropic, grok
    pub api_provider: Option<String>,
    /// Deprecated: use api_key instead
    pub api_keys_encrypted: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitAgentResponse {
    pub success: bool,
    pub submission_id: Option<String>,
    pub agent_hash: Option<String>,
    pub error: Option<String>,
}

// ============================================================================
// EVALUATION
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evaluation {
    pub id: String,
    pub submission_id: String,
    pub agent_hash: String,
    pub validator_hotkey: String,
    pub score: f64,
    pub tasks_passed: u32,
    pub tasks_total: u32,
    pub tasks_failed: u32,
    pub total_cost_usd: f64,
    pub execution_time_ms: Option<i64>,
    pub task_results: Option<String>,
    pub execution_log: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitEvaluationRequest {
    pub submission_id: String,
    pub agent_hash: String,
    pub validator_hotkey: String,
    pub signature: String,
    pub score: f64,
    pub tasks_passed: u32,
    pub tasks_total: u32,
    pub tasks_failed: u32,
    pub total_cost_usd: f64,
    pub execution_time_ms: Option<i64>,
    pub task_results: Option<serde_json::Value>,
    pub execution_log: Option<String>,
}

// ============================================================================
// LEADERBOARD
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderboardEntry {
    pub agent_hash: String,
    pub miner_hotkey: String,
    pub name: Option<String>,
    pub consensus_score: f64,
    pub evaluation_count: u32,
    pub rank: u32,
    pub first_epoch: u64,
    pub last_epoch: u64,
    pub best_rank: Option<u32>,
    pub total_rewards: f64,
    pub updated_at: i64,
}

// ============================================================================
// CHALLENGE CONFIG (kept for API compatibility)
// ============================================================================

#[allow(dead_code)] // API model, constructed via serde
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeConfig {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    /// Mechanism ID for Bittensor (each challenge = one mechanism)
    pub mechanism_id: u8,
    /// Emission weight for this challenge (0.0 - 1.0)
    /// Remaining weight (1.0 - emission_weight) goes to UID 0 (burn)
    pub emission_weight: f64,
    /// Challenge version (for updates)
    pub version: String,
    /// Challenge status (active, paused, deprecated)
    pub status: ChallengeStatus,
    pub max_agents_per_epoch: f64,
    pub min_stake: u64,
    pub module_whitelist: Option<Vec<String>>,
    pub model_whitelist: Option<Vec<String>>,
    pub pricing_config: Option<PricingConfig>,
    pub evaluation_config: Option<EvaluationConfig>,
    pub updated_at: i64,
    pub updated_by: Option<String>,
}

#[allow(dead_code)] // Used via serde
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Active,
    Paused,
    Deprecated,
}

#[allow(dead_code)] // Nested in ChallengeConfig
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingConfig {
    pub max_cost_per_task: f64,
    pub max_total_cost: f64,
}

#[allow(dead_code)] // Nested in ChallengeConfig
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationConfig {
    pub max_tasks: u32,
    pub timeout_seconds: u32,
    pub max_steps_per_task: u32,
}

#[allow(dead_code)] // API model, constructed via serde
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfigRequest {
    pub owner_hotkey: String,
    pub signature: String,
    pub config: serde_json::Value,
}

// ============================================================================
// TASK LEASE (Claim/Lease Anti-Duplication Mechanism)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskLease {
    pub task_id: String,
    pub validator_hotkey: String,
    pub claimed_at: i64,
    pub expires_at: i64,
    pub status: TaskLeaseStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TaskLeaseStatus {
    Active,
    Completed,
    Failed,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimTaskRequest {
    pub task_id: String,
    pub validator_hotkey: String,
    pub signature: String,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimTaskResponse {
    pub success: bool,
    pub lease: Option<TaskLease>,
    pub error: Option<String>,
}

// ============================================================================
// WEBSOCKET EVENTS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum WsEvent {
    #[serde(rename = "submission_received")]
    SubmissionReceived(SubmissionEvent),

    #[serde(rename = "evaluation_complete")]
    EvaluationComplete(EvaluationEvent),

    #[serde(rename = "leaderboard_updated")]
    LeaderboardUpdated(LeaderboardUpdateEvent),

    #[serde(rename = "challenge_updated")]
    ChallengeUpdated(ChallengeUpdateEvent),

    #[serde(rename = "challenge_registered")]
    ChallengeRegistered(ChallengeRegisteredEvent),

    #[serde(rename = "challenge_started")]
    ChallengeStarted(ChallengeStartedEvent),

    #[serde(rename = "challenge_stopped")]
    ChallengeStopped(ChallengeStoppedEvent),

    #[serde(rename = "validator_joined")]
    ValidatorJoined(ValidatorEvent),

    #[serde(rename = "validator_left")]
    ValidatorLeft(ValidatorEvent),

    #[serde(rename = "network_state")]
    NetworkState(NetworkStateEvent),

    #[serde(rename = "task_claimed")]
    TaskClaimed(TaskClaimedEvent),

    #[serde(rename = "job_assigned")]
    JobAssigned(JobAssignedEvent),

    /// Custom challenge event - each challenge can define its own event types
    /// Validators filter by challenge_id to receive only relevant events
    #[serde(rename = "challenge_event")]
    ChallengeEvent(ChallengeCustomEvent),

    #[serde(rename = "job_progress")]
    JobProgress(JobProgressEvent),

    #[serde(rename = "job_completed")]
    JobCompleted(JobCompletedEvent),

    #[serde(rename = "ping")]
    Ping,

    #[serde(rename = "pong")]
    Pong,
}

// ============================================================================
// EVALUATION JOB QUEUE (used via serde in WsEvent)
// ============================================================================

/// Evaluation job to be assigned to validators
#[allow(dead_code)] // Constructed via serde deserialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationJob {
    pub id: String,
    pub submission_id: String,
    pub agent_hash: String,
    pub miner_hotkey: String,
    pub source_code: String,
    pub api_key: Option<String>,
    pub api_provider: Option<String>,
    pub challenge_id: String,
    pub created_at: i64,
    pub status: JobStatus,
    pub assigned_validator: Option<String>,
    pub assigned_at: Option<i64>,
}

#[allow(dead_code)] // Used via serde
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Pending,
    Assigned,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobAssignedEvent {
    pub job_id: String,
    pub submission_id: String,
    pub agent_hash: String,
    pub validator_hotkey: String,
    pub challenge_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobProgressEvent {
    pub job_id: String,
    pub validator_hotkey: String,
    pub task_index: u32,
    pub task_total: u32,
    pub task_id: String,
    pub status: TaskProgressStatus,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TaskProgressStatus {
    Started,
    Running,
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobCompletedEvent {
    pub job_id: String,
    pub validator_hotkey: String,
    pub submission_id: String,
    pub agent_hash: String,
    pub score: f64,
    pub tasks_passed: u32,
    pub tasks_total: u32,
    pub total_cost_usd: f64,
    pub execution_time_ms: u64,
    pub task_results: Vec<TaskResultSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResultSummary {
    pub task_id: String,
    pub passed: bool,
    pub score: f64,
    pub cost_usd: f64,
    pub execution_time_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionEvent {
    pub submission_id: String,
    pub agent_hash: String,
    pub miner_hotkey: String,
    pub name: Option<String>,
    pub epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationEvent {
    pub submission_id: String,
    pub agent_hash: String,
    pub validator_hotkey: String,
    pub score: f64,
    pub tasks_passed: u32,
    pub tasks_total: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderboardUpdateEvent {
    pub agent_hash: String,
    pub new_rank: u32,
    pub old_rank: Option<u32>,
    pub consensus_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeUpdateEvent {
    pub field: String,
    pub old_value: Option<String>,
    pub new_value: String,
    pub updated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRegisteredEvent {
    pub id: String,
    pub name: String,
    pub docker_image: String,
    pub mechanism_id: u8,
    pub emission_weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeStartedEvent {
    pub id: String,
    pub endpoint: String,
    pub docker_image: String,
    pub mechanism_id: u8,
    pub emission_weight: f64,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_cpu")]
    pub cpu_cores: f64,
    #[serde(default = "default_memory")]
    pub memory_mb: u64,
    #[serde(default)]
    pub gpu_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeStoppedEvent {
    pub id: String,
}

/// Custom event from a challenge - allows challenges to broadcast their own events
/// Validators subscribe and filter by challenge_id
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeCustomEvent {
    /// Challenge identifier (e.g., "term-challenge")
    pub challenge_id: String,
    /// Event name within the challenge (e.g., "new_submission", "evaluation_needed")
    pub event_name: String,
    /// Event payload as JSON - challenge-specific data
    pub payload: serde_json::Value,
    /// Timestamp when event was created
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorEvent {
    pub hotkey: String,
    pub stake: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStateEvent {
    pub current_epoch: u64,
    pub current_block: u64,
    pub tempo: u64,
    pub total_stake: u64,
    pub active_validators: u32,
    pub pending_submissions: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskClaimedEvent {
    pub task_id: String,
    pub validator_hotkey: String,
    pub expires_at: i64,
}

// ============================================================================
// AUTH
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub hotkey: String,
    pub timestamp: i64,
    pub signature: String,
    pub role: AuthRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuthRole {
    Validator,
    Miner,
    Owner,
    Challenge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub success: bool,
    pub token: Option<String>,
    pub expires_at: Option<i64>,
    pub error: Option<String>,
}

#[allow(dead_code)] // Fields stored but not yet read (session lookup removed)
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub hotkey: String,
    pub role: AuthRole,
    pub expires_at: i64,
}

// ============================================================================
// DATA API
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteResultRequest {
    pub agent_hash: String,
    pub validator_hotkey: String,
    pub signature: String,
    pub score: f64,
    pub task_results: Option<serde_json::Value>,
    pub execution_time_ms: Option<i64>,
}

// ============================================================================
// REGISTERED CHALLENGES (Dynamic Orchestration)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredChallenge {
    pub id: String,
    pub name: String,
    pub docker_image: String,
    pub mechanism_id: u8,
    pub emission_weight: f64,
    pub timeout_secs: u64,
    pub cpu_cores: f64,
    pub memory_mb: u64,
    pub gpu_required: bool,
    pub status: String,
    pub endpoint: Option<String>,
    pub container_id: Option<String>,
    pub last_health_check: Option<i64>,
    pub is_healthy: bool,
}

impl RegisteredChallenge {
    #[allow(dead_code)] // Used by bins/platform
    pub fn new(id: &str, name: &str, docker_image: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            docker_image: docker_image.to_string(),
            mechanism_id: 1,
            emission_weight: 0.1,
            timeout_secs: 3600,
            cpu_cores: 2.0,
            memory_mb: 4096,
            gpu_required: false,
            status: "active".to_string(),
            endpoint: None,
            container_id: None,
            last_health_check: None,
            is_healthy: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterChallengeRequest {
    pub id: String,
    pub name: String,
    pub docker_image: String,
    #[serde(default = "default_mechanism_id")]
    pub mechanism_id: u8,
    #[serde(default = "default_emission_weight")]
    pub emission_weight: f64,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_cpu")]
    pub cpu_cores: f64,
    #[serde(default = "default_memory")]
    pub memory_mb: u64,
    #[serde(default)]
    pub gpu_required: bool,
    pub owner_hotkey: String,
    pub signature: String,
}

fn default_mechanism_id() -> u8 {
    1
}
fn default_emission_weight() -> f64 {
    0.1
}
fn default_timeout() -> u64 {
    3600
}
fn default_cpu() -> f64 {
    2.0
}
fn default_memory() -> u64 {
    4096
}

/// Request to start/stop a challenge (requires owner signature)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeActionRequest {
    pub owner_hotkey: String,
    pub signature: String,
    pub timestamp: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_submission_status_to_string() {
        assert_eq!(SubmissionStatus::Pending.to_string(), "pending");
        assert_eq!(SubmissionStatus::Evaluating.to_string(), "evaluating");
        assert_eq!(SubmissionStatus::Completed.to_string(), "completed");
        assert_eq!(SubmissionStatus::Failed.to_string(), "failed");
        assert_eq!(SubmissionStatus::Rejected.to_string(), "rejected");
    }

    #[test]
    fn test_submission_status_from_str() {
        assert_eq!(SubmissionStatus::from("pending"), SubmissionStatus::Pending);
        assert_eq!(
            SubmissionStatus::from("evaluating"),
            SubmissionStatus::Evaluating
        );
        assert_eq!(
            SubmissionStatus::from("completed"),
            SubmissionStatus::Completed
        );
        assert_eq!(SubmissionStatus::from("failed"), SubmissionStatus::Failed);
        assert_eq!(
            SubmissionStatus::from("rejected"),
            SubmissionStatus::Rejected
        );
        // Default case
        assert_eq!(SubmissionStatus::from("unknown"), SubmissionStatus::Pending);
    }

    #[test]
    fn test_submission_status_equality() {
        assert_eq!(SubmissionStatus::Pending, SubmissionStatus::Pending);
        assert_ne!(SubmissionStatus::Pending, SubmissionStatus::Completed);
    }

    #[test]
    fn test_challenge_status_equality() {
        assert_eq!(ChallengeStatus::Active, ChallengeStatus::Active);
        assert_ne!(ChallengeStatus::Active, ChallengeStatus::Paused);
        assert_ne!(ChallengeStatus::Paused, ChallengeStatus::Deprecated);
    }

    #[test]
    fn test_task_lease_status_equality() {
        assert_eq!(TaskLeaseStatus::Active, TaskLeaseStatus::Active);
        assert_ne!(TaskLeaseStatus::Active, TaskLeaseStatus::Completed);
        assert_ne!(TaskLeaseStatus::Completed, TaskLeaseStatus::Failed);
        assert_ne!(TaskLeaseStatus::Failed, TaskLeaseStatus::Expired);
    }

    #[test]
    fn test_auth_role_equality() {
        assert_eq!(AuthRole::Validator, AuthRole::Validator);
        assert_ne!(AuthRole::Validator, AuthRole::Miner);
        assert_ne!(AuthRole::Miner, AuthRole::Owner);
        assert_ne!(AuthRole::Owner, AuthRole::Challenge);
    }

    #[test]
    fn test_job_status_equality() {
        assert_eq!(JobStatus::Pending, JobStatus::Pending);
        assert_ne!(JobStatus::Pending, JobStatus::Assigned);
        assert_ne!(JobStatus::Assigned, JobStatus::Running);
        assert_ne!(JobStatus::Running, JobStatus::Completed);
        assert_ne!(JobStatus::Completed, JobStatus::Failed);
    }

    #[test]
    fn test_task_progress_status_equality() {
        assert_eq!(TaskProgressStatus::Started, TaskProgressStatus::Started);
        assert_ne!(TaskProgressStatus::Started, TaskProgressStatus::Running);
        assert_ne!(TaskProgressStatus::Running, TaskProgressStatus::Passed);
        assert_ne!(TaskProgressStatus::Passed, TaskProgressStatus::Failed);
        assert_ne!(TaskProgressStatus::Failed, TaskProgressStatus::Skipped);
    }

    #[test]
    fn test_registered_challenge_new() {
        let challenge = RegisteredChallenge::new(
            "test-challenge",
            "Test Challenge",
            "test-image:latest",
        );

        assert_eq!(challenge.id, "test-challenge");
        assert_eq!(challenge.name, "Test Challenge");
        assert_eq!(challenge.docker_image, "test-image:latest");
        assert_eq!(challenge.mechanism_id, 1);
        assert_eq!(challenge.emission_weight, 0.1);
        assert_eq!(challenge.timeout_secs, 3600);
        assert_eq!(challenge.cpu_cores, 2.0);
        assert_eq!(challenge.memory_mb, 4096);
        assert_eq!(challenge.gpu_required, false);
        assert_eq!(challenge.status, "active");
        assert_eq!(challenge.endpoint, None);
        assert_eq!(challenge.container_id, None);
        assert_eq!(challenge.last_health_check, None);
        assert_eq!(challenge.is_healthy, false);
    }

    #[test]
    fn test_default_functions() {
        assert_eq!(default_mechanism_id(), 1);
        assert_eq!(default_emission_weight(), 0.1);
        assert_eq!(default_timeout(), 3600);
        assert_eq!(default_cpu(), 2.0);
        assert_eq!(default_memory(), 4096);
    }

    #[test]
    fn test_validator_serialization() {
        let validator = Validator {
            hotkey: "test_hotkey".to_string(),
            stake: 1000,
            last_seen: Some(1234567890),
            is_active: true,
            created_at: 1234567800,
        };

        let json = serde_json::to_string(&validator).unwrap();
        assert!(json.contains("test_hotkey"));
        assert!(json.contains("1000"));

        let deserialized: Validator = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.hotkey, "test_hotkey");
        assert_eq!(deserialized.stake, 1000);
    }

    #[test]
    fn test_submission_serialization() {
        let submission = Submission {
            id: "sub-123".to_string(),
            agent_hash: "hash123".to_string(),
            miner_hotkey: "miner1".to_string(),
            source_code: Some("code".to_string()),
            source_hash: "src_hash".to_string(),
            name: Some("Agent 1".to_string()),
            version: "1.0.0".to_string(),
            epoch: 10,
            status: SubmissionStatus::Pending,
            api_key: Some("key123".to_string()),
            api_provider: Some("openrouter".to_string()),
            total_cost_usd: Some(1.5),
            api_keys_encrypted: None,
            created_at: 1234567890,
        };

        let json = serde_json::to_string(&submission).unwrap();
        let deserialized: Submission = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "sub-123");
        assert_eq!(deserialized.agent_hash, "hash123");
        assert_eq!(deserialized.status, SubmissionStatus::Pending);
    }

    #[test]
    fn test_evaluation_serialization() {
        let evaluation = Evaluation {
            id: "eval-123".to_string(),
            submission_id: "sub-123".to_string(),
            agent_hash: "hash123".to_string(),
            validator_hotkey: "validator1".to_string(),
            score: 0.95,
            tasks_passed: 19,
            tasks_total: 20,
            tasks_failed: 1,
            total_cost_usd: 2.5,
            execution_time_ms: Some(5000),
            task_results: Some("results".to_string()),
            execution_log: Some("log".to_string()),
            created_at: 1234567890,
        };

        let json = serde_json::to_string(&evaluation).unwrap();
        let deserialized: Evaluation = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.score, 0.95);
        assert_eq!(deserialized.tasks_passed, 19);
    }

    #[test]
    fn test_task_lease_serialization() {
        let lease = TaskLease {
            task_id: "task-123".to_string(),
            validator_hotkey: "validator1".to_string(),
            claimed_at: 1234567890,
            expires_at: 1234568190,
            status: TaskLeaseStatus::Active,
        };

        let json = serde_json::to_string(&lease).unwrap();
        let deserialized: TaskLease = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.task_id, "task-123");
        assert_eq!(deserialized.status, TaskLeaseStatus::Active);
    }

    #[test]
    fn test_ws_event_serialization() {
        let event = WsEvent::Ping;
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("ping"));

        let event = WsEvent::Pong;
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("pong"));
    }

    #[test]
    fn test_ws_event_submission_received() {
        let event = WsEvent::SubmissionReceived(SubmissionEvent {
            submission_id: "sub-123".to_string(),
            agent_hash: "hash123".to_string(),
            miner_hotkey: "miner1".to_string(),
            name: Some("Agent 1".to_string()),
            epoch: 10,
        });

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("submission_received"));
        assert!(json.contains("sub-123"));
    }

    #[test]
    fn test_ws_event_task_claimed() {
        let event = WsEvent::TaskClaimed(TaskClaimedEvent {
            task_id: "task-123".to_string(),
            validator_hotkey: "validator1".to_string(),
            expires_at: 1234568190,
        });

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("task_claimed"));
        assert!(json.contains("task-123"));
    }

    #[test]
    fn test_challenge_custom_event_serialization() {
        let event = WsEvent::ChallengeEvent(ChallengeCustomEvent {
            challenge_id: "test-challenge".to_string(),
            event_name: "custom_event".to_string(),
            payload: serde_json::json!({"key": "value"}),
            timestamp: 1234567890,
        });

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("challenge_event"));
        assert!(json.contains("test-challenge"));
        assert!(json.contains("custom_event"));
    }

    #[test]
    fn test_auth_request_serialization() {
        let request = AuthRequest {
            hotkey: "validator1".to_string(),
            timestamp: 1234567890,
            signature: "sig123".to_string(),
            role: AuthRole::Validator,
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: AuthRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.hotkey, "validator1");
        assert_eq!(deserialized.role, AuthRole::Validator);
    }

    #[test]
    fn test_job_assigned_event_serialization() {
        let event = WsEvent::JobAssigned(JobAssignedEvent {
            job_id: "job-123".to_string(),
            submission_id: "sub-123".to_string(),
            agent_hash: "hash123".to_string(),
            validator_hotkey: "validator1".to_string(),
            challenge_id: "challenge-1".to_string(),
        });

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("job_assigned"));
        assert!(json.contains("job-123"));
    }

    #[test]
    fn test_job_progress_event_serialization() {
        let event = WsEvent::JobProgress(JobProgressEvent {
            job_id: "job-123".to_string(),
            validator_hotkey: "validator1".to_string(),
            task_index: 5,
            task_total: 10,
            task_id: "task-5".to_string(),
            status: TaskProgressStatus::Running,
            message: Some("Running test".to_string()),
        });

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("job_progress"));
        assert!(json.contains("task-5"));
    }

    #[test]
    fn test_challenge_registered_event_serialization() {
        let event = WsEvent::ChallengeRegistered(ChallengeRegisteredEvent {
            id: "challenge-1".to_string(),
            name: "Test Challenge".to_string(),
            docker_image: "test:latest".to_string(),
            mechanism_id: 1,
            emission_weight: 0.2,
        });

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("challenge_registered"));
        assert!(json.contains("Test Challenge"));
    }

    #[test]
    fn test_challenge_started_event_serialization() {
        let event = WsEvent::ChallengeStarted(ChallengeStartedEvent {
            id: "challenge-1".to_string(),
            endpoint: "http://localhost:8080".to_string(),
            docker_image: "test:latest".to_string(),
            mechanism_id: 1,
            emission_weight: 0.2,
            timeout_secs: 3600,
            cpu_cores: 2.0,
            memory_mb: 4096,
            gpu_required: false,
        });

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("challenge_started"));
        assert!(json.contains("localhost:8080"));
    }
}
