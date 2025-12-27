//! Observability - Sentry Integration and Audit Trail
//!
//! Provides:
//! - Sentry error tracking (enabled via SENTRY_DSN env var)
//! - Structured audit logging for all data access
//! - Performance monitoring
//! - Full data-access audit trail as per architecture spec

use crate::db::queries;
use crate::state::AppState;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{error, info, span, warn, Level};

/// Initialize Sentry if SENTRY_DSN is set
pub fn init_sentry() -> Option<sentry::ClientInitGuard> {
    let dsn = std::env::var("SENTRY_DSN").ok()?;

    if dsn.is_empty() {
        info!("Sentry DSN is empty, error tracking disabled");
        return None;
    }

    let guard = sentry::init((
        dsn,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            environment: std::env::var("ENVIRONMENT").ok().map(|s| s.into()),
            traces_sample_rate: 0.1, // 10% of transactions
            ..Default::default()
        },
    ));

    info!("Sentry initialized for error tracking");
    Some(guard)
}

/// Audit event types for full data-access trail
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    // Authentication
    AuthSuccess,
    AuthFailed,
    SessionCreated,
    SessionExpired,

    // Submissions
    SubmissionCreated,
    SubmissionValidated,
    SubmissionRejected,
    SubmissionStatusChanged,

    // Evaluations
    EvaluationStarted,
    EvaluationCompleted,
    EvaluationFailed,

    // Task Claims (Lease)
    TaskClaimed,
    TaskRenewed,
    TaskAcknowledged,
    TaskFailed,
    TaskExpired,

    // Config Changes
    ConfigUpdated,
    ChallengeStatusChanged,

    // Validator Activity
    ValidatorRegistered,
    ValidatorHeartbeat,
    ValidatorDeactivated,

    // Weight Calculation
    WeightsRequested,
    WeightsComputed,
    SnapshotCreated,

    // Security Events
    RateLimitExceeded,
    UnauthorizedAccess,
    PolicyViolation,
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string(self).unwrap_or_else(|_| "unknown".to_string());
        write!(f, "{}", s.trim_matches('"'))
    }
}

/// Structured audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub event_type: AuditEventType,
    pub entity_type: Option<String>,
    pub entity_id: Option<String>,
    pub actor_hotkey: Option<String>,
    pub actor_role: Option<String>,
    pub ip_address: Option<String>,
    pub payload: Option<serde_json::Value>,
    pub duration_ms: Option<u64>,
    pub success: bool,
    pub error_message: Option<String>,
}

impl AuditEntry {
    pub fn new(event_type: AuditEventType) -> Self {
        Self {
            event_type,
            entity_type: None,
            entity_id: None,
            actor_hotkey: None,
            actor_role: None,
            ip_address: None,
            payload: None,
            duration_ms: None,
            success: true,
            error_message: None,
        }
    }

    pub fn entity(mut self, entity_type: &str, entity_id: &str) -> Self {
        self.entity_type = Some(entity_type.to_string());
        self.entity_id = Some(entity_id.to_string());
        self
    }

    pub fn actor(mut self, hotkey: &str, role: Option<&str>) -> Self {
        self.actor_hotkey = Some(hotkey.to_string());
        self.actor_role = role.map(|s| s.to_string());
        self
    }

    pub fn with_payload(mut self, payload: serde_json::Value) -> Self {
        self.payload = Some(payload);
        self
    }

    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    pub fn failed(mut self, error: &str) -> Self {
        self.success = false;
        self.error_message = Some(error.to_string());
        self
    }
}

/// Audit logger for structured logging and persistence
pub struct AuditLogger;

impl AuditLogger {
    /// Log an audit event to both tracing and database
    pub async fn log(state: &AppState, entry: AuditEntry) {
        // Create structured log
        let span = span!(
            Level::INFO,
            "audit",
            event_type = %entry.event_type,
            entity_type = ?entry.entity_type,
            entity_id = ?entry.entity_id,
            actor = ?entry.actor_hotkey,
            success = entry.success,
        );
        let _guard = span.enter();

        if entry.success {
            info!(
                event = %entry.event_type,
                entity = ?entry.entity_id,
                actor = ?entry.actor_hotkey,
                duration_ms = ?entry.duration_ms,
                "Audit event"
            );
        } else {
            warn!(
                event = %entry.event_type,
                entity = ?entry.entity_id,
                actor = ?entry.actor_hotkey,
                error = ?entry.error_message,
                "Audit event failed"
            );

            // Report to Sentry if it's a failure
            if let Some(ref msg) = entry.error_message {
                sentry::capture_message(
                    &format!("{}: {}", entry.event_type, msg),
                    sentry::Level::Warning,
                );
            }
        }

        // Persist to database
        let payload_str = entry
            .payload
            .as_ref()
            .map(|p| serde_json::to_string(p).unwrap_or_default());

        if let Err(e) = queries::log_event(
            &state.db,
            &entry.event_type.to_string(),
            entry.entity_type.as_deref(),
            entry.entity_id.as_deref(),
            payload_str.as_deref(),
            entry.actor_hotkey.as_deref(),
        )
        .await
        {
            error!(error = %e, "Failed to persist audit event");
        }
    }

    /// Log authentication event
    pub async fn auth(
        state: &AppState,
        hotkey: &str,
        role: &str,
        success: bool,
        error: Option<&str>,
    ) {
        let mut entry = AuditEntry::new(if success {
            AuditEventType::AuthSuccess
        } else {
            AuditEventType::AuthFailed
        })
        .actor(hotkey, Some(role));

        if let Some(e) = error {
            entry = entry.failed(e);
        }

        Self::log(state, entry).await;
    }

    /// Log submission event
    pub async fn submission(
        state: &AppState,
        event: AuditEventType,
        submission_id: &str,
        agent_hash: &str,
        miner_hotkey: &str,
    ) {
        let entry = AuditEntry::new(event)
            .entity("submission", submission_id)
            .actor(miner_hotkey, Some("miner"))
            .with_payload(serde_json::json!({
                "agent_hash": agent_hash,
            }));

        Self::log(state, entry).await;
    }

    /// Log evaluation event
    pub async fn evaluation(
        state: &AppState,
        event: AuditEventType,
        submission_id: &str,
        agent_hash: &str,
        validator_hotkey: &str,
        score: Option<f64>,
        duration_ms: Option<u64>,
    ) {
        let mut entry = AuditEntry::new(event)
            .entity("evaluation", submission_id)
            .actor(validator_hotkey, Some("validator"))
            .with_payload(serde_json::json!({
                "agent_hash": agent_hash,
                "score": score,
            }));

        if let Some(d) = duration_ms {
            entry = entry.with_duration(d);
        }

        Self::log(state, entry).await;
    }

    /// Log task claim/lease event
    pub async fn task_lease(
        state: &AppState,
        event: AuditEventType,
        task_id: &str,
        validator_hotkey: &str,
        ttl_seconds: Option<u64>,
    ) {
        let entry = AuditEntry::new(event)
            .entity("task_lease", task_id)
            .actor(validator_hotkey, Some("validator"))
            .with_payload(serde_json::json!({
                "ttl_seconds": ttl_seconds,
            }));

        Self::log(state, entry).await;
    }

    /// Log weight calculation event
    pub async fn weights(
        state: &AppState,
        epoch: u64,
        num_weights: usize,
        total_weight: f64,
        duration_ms: u64,
    ) {
        let entry = AuditEntry::new(AuditEventType::WeightsComputed)
            .entity("epoch", &epoch.to_string())
            .with_payload(serde_json::json!({
                "num_weights": num_weights,
                "total_weight": total_weight,
            }))
            .with_duration(duration_ms);

        Self::log(state, entry).await;
    }

    /// Log security event
    pub async fn security(state: &AppState, event: AuditEventType, hotkey: &str, details: &str) {
        let event_str = event.to_string();
        let entry = AuditEntry::new(event).actor(hotkey, None).failed(details);

        Self::log(state, entry).await;

        // Always report security events to Sentry
        sentry::capture_message(
            &format!("Security event: {} - {} - {}", event_str, hotkey, details),
            sentry::Level::Warning,
        );
    }
}

/// Timer for measuring operation duration
pub struct OperationTimer {
    start: Instant,
}

impl OperationTimer {
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_entry_builder() {
        let entry = AuditEntry::new(AuditEventType::SubmissionCreated)
            .entity("submission", "sub-123")
            .actor("hotkey123", Some("miner"))
            .with_payload(serde_json::json!({"test": true}))
            .with_duration(100);

        assert!(entry.success);
        assert_eq!(entry.entity_id, Some("sub-123".to_string()));
        assert_eq!(entry.actor_hotkey, Some("hotkey123".to_string()));
        assert_eq!(entry.duration_ms, Some(100));
    }

    #[test]
    fn test_audit_entry_failed() {
        let entry = AuditEntry::new(AuditEventType::AuthFailed)
            .actor("hotkey123", Some("validator"))
            .failed("Invalid signature");

        assert!(!entry.success);
        assert_eq!(entry.error_message, Some("Invalid signature".to_string()));
    }
}
