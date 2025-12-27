//! Rule Engine - Server-Side Enforcement
//!
//! The Rule Engine enforces challenge-defined rules server-side:
//! - Prevents flooding (rate limiting)
//! - Prevents duplicate processing (via Claim/Lease)
//! - Prevents unauthorized access (auth checks)
//! - Full audit trail
//!
//! This is a critical security component that ensures:
//! - Challenges cannot bypass rules
//! - All data access is audited
//! - Rate limits are enforced globally

use crate::db::queries;
use crate::models::*;
use crate::state::AppState;
use anyhow::{anyhow, Result};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Rate limit configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per window
    pub max_requests: u32,
    /// Window duration
    pub window_duration: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window_duration: Duration::from_secs(60),
        }
    }
}

/// Rule Engine for server-side enforcement
pub struct RuleEngine {
    /// Rate limit tracking per hotkey
    rate_limits: RwLock<HashMap<String, RateLimitEntry>>,
    /// Configuration
    config: RateLimitConfig,
}

struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            rate_limits: RwLock::new(HashMap::new()),
            config: RateLimitConfig::default(),
        }
    }

    pub fn with_config(config: RateLimitConfig) -> Self {
        Self {
            rate_limits: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Check rate limit for a hotkey
    /// Returns Ok(()) if allowed, Err if rate limited
    pub fn check_rate_limit(&self, hotkey: &str) -> Result<()> {
        let mut limits = self.rate_limits.write();
        let now = Instant::now();

        let entry = limits.entry(hotkey.to_string()).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if now.duration_since(entry.window_start) > self.config.window_duration {
            entry.count = 0;
            entry.window_start = now;
        }

        // Check limit
        if entry.count >= self.config.max_requests {
            warn!(hotkey = %hotkey, "Rate limit exceeded");
            return Err(anyhow!("Rate limit exceeded. Try again later."));
        }

        entry.count += 1;
        Ok(())
    }

    /// Validate submission rules
    pub async fn validate_submission(
        &self,
        state: &AppState,
        miner_hotkey: &str,
        source_code: &str,
    ) -> Result<()> {
        // Check rate limit
        self.check_rate_limit(miner_hotkey)?;

        // Check source code size
        if source_code.len() > 1_000_000 {
            return Err(anyhow!("Source code exceeds maximum size (1MB)"));
        }

        if source_code.is_empty() {
            return Err(anyhow!("Source code cannot be empty"));
        }

        // Check for duplicate submission in same epoch
        let epoch = queries::get_current_epoch(&state.db).await?;
        let existing = queries::get_pending_submissions(&state.db).await?;

        let hash = queries::compute_agent_hash(miner_hotkey, source_code);
        if existing.iter().any(|s| s.agent_hash == hash) {
            return Err(anyhow!("Duplicate submission already exists"));
        }

        Ok(())
    }

    /// Validate evaluation rules
    pub async fn validate_evaluation(
        &self,
        state: &AppState,
        validator_hotkey: &str,
        agent_hash: &str,
    ) -> Result<()> {
        // Check rate limit
        self.check_rate_limit(validator_hotkey)?;

        // Check validator exists
        let validator = queries::get_validator(&state.db, validator_hotkey).await?;
        if validator.is_none() {
            return Err(anyhow!("Validator not registered"));
        }

        // Check submission exists
        let submission = queries::get_submission_by_hash(&state.db, agent_hash).await?;
        if submission.is_none() {
            return Err(anyhow!("Agent not found: {}", agent_hash));
        }

        Ok(())
    }

    /// Validate task claim rules
    pub fn validate_claim(
        &self,
        state: &AppState,
        task_id: &str,
        validator_hotkey: &str,
    ) -> Result<()> {
        // Check rate limit
        self.check_rate_limit(validator_hotkey)?;

        // Check if task is already claimed by another validator
        if let Some(existing) = state.task_leases.get(task_id) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            if existing.validator_hotkey != validator_hotkey && existing.expires_at > now {
                return Err(anyhow!(
                    "Task already claimed by another validator until {}",
                    existing.expires_at
                ));
            }
        }

        Ok(())
    }

    /// Log an audit event
    pub async fn audit(
        &self,
        state: &AppState,
        event_type: &str,
        entity_type: Option<&str>,
        entity_id: Option<&str>,
        payload: Option<&str>,
        actor: Option<&str>,
    ) -> Result<()> {
        queries::log_event(
            &state.db,
            event_type,
            entity_type,
            entity_id,
            payload,
            actor,
        )
        .await?;
        info!(
            event = %event_type,
            entity_type = ?entity_type,
            entity_id = ?entity_id,
            actor = ?actor,
            "Audit event logged"
        );
        Ok(())
    }

    /// Clean up expired rate limit entries
    pub fn cleanup_expired(&self) {
        let mut limits = self.rate_limits.write();
        let now = Instant::now();
        limits.retain(|_, entry| {
            now.duration_since(entry.window_start) <= self.config.window_duration
        });
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit() {
        let engine = RuleEngine::with_config(RateLimitConfig {
            max_requests: 3,
            window_duration: Duration::from_secs(60),
        });

        let hotkey = "test_hotkey";

        // First 3 requests should pass
        assert!(engine.check_rate_limit(hotkey).is_ok());
        assert!(engine.check_rate_limit(hotkey).is_ok());
        assert!(engine.check_rate_limit(hotkey).is_ok());

        // 4th request should fail
        assert!(engine.check_rate_limit(hotkey).is_err());
    }

    #[test]
    fn test_rate_limit_different_hotkeys() {
        let engine = RuleEngine::with_config(RateLimitConfig {
            max_requests: 1,
            window_duration: Duration::from_secs(60),
        });

        // Each hotkey has its own limit
        assert!(engine.check_rate_limit("hotkey1").is_ok());
        assert!(engine.check_rate_limit("hotkey2").is_ok());

        // But can't exceed individual limits
        assert!(engine.check_rate_limit("hotkey1").is_err());
    }
}
