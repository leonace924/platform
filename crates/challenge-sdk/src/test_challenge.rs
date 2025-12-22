//! Simple test challenge for integration testing

use crate::{
    AgentInfo, Challenge, ChallengeContext, ChallengeId, EvaluationResult, Result, WeightAssignment,
};
use async_trait::async_trait;
use serde_json::Value;

/// Simple test challenge that returns random scores
pub struct SimpleTestChallenge {
    id: ChallengeId,
    name: String,
    emission_weight: f64,
}

impl SimpleTestChallenge {
    pub fn new(name: impl Into<String>, emission_weight: f64) -> Self {
        Self {
            id: ChallengeId::new(),
            name: name.into(),
            emission_weight,
        }
    }

    pub fn with_id(mut self, id: ChallengeId) -> Self {
        self.id = id;
        self
    }
}

impl Default for SimpleTestChallenge {
    fn default() -> Self {
        Self::new("Simple Test Challenge", 1.0)
    }
}

#[async_trait]
impl Challenge for SimpleTestChallenge {
    fn id(&self) -> ChallengeId {
        self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "A simple test challenge for integration testing"
    }

    fn emission_weight(&self) -> f64 {
        self.emission_weight
    }

    async fn evaluate(
        &self,
        ctx: &ChallengeContext,
        agent: &AgentInfo,
        payload: Value,
    ) -> Result<EvaluationResult> {
        ctx.info(&format!("Evaluating agent: {}", agent.hash));

        // Simple scoring based on agent hash length and payload
        let base_score = (agent.hash.len() as f64 / 100.0).min(1.0);

        // Add some variation based on payload
        let payload_bonus = if let Some(bonus) = payload.get("bonus").and_then(|v| v.as_f64()) {
            bonus.clamp(0.0, 0.2)
        } else {
            0.0
        };

        let score = (base_score + payload_bonus).clamp(0.0, 1.0);

        // Save agent to DB
        ctx.db().save_agent(agent)?;

        let result = EvaluationResult::new(ctx.job_id(), agent.hash.clone(), score).with_reason(
            format!("Base: {:.2}, Bonus: {:.2}", base_score, payload_bonus),
        );

        ctx.info(&format!("Agent {} scored {:.4}", agent.hash, score));

        Ok(result)
    }

    async fn calculate_weights(&self, ctx: &ChallengeContext) -> Result<Vec<WeightAssignment>> {
        ctx.info("Calculating weights");

        // Get latest results from DB
        let results = ctx.db().get_latest_results()?;

        if results.is_empty() {
            ctx.warn("No results to calculate weights from");
            return Ok(vec![]);
        }

        // Convert scores to weights
        // Note: In real challenges, agent_hash would be mapped to miner hotkey
        // Here we use agent_hash as hotkey for testing
        let scores: Vec<(String, f64)> = results
            .iter()
            .map(|r| (r.agent_hash.clone(), r.score))
            .collect();

        let weights = crate::weights::scores_to_weights(&scores);

        ctx.info(&format!("Calculated weights for {} miners", weights.len()));

        Ok(weights)
    }

    async fn on_startup(&self, ctx: &ChallengeContext) -> Result<()> {
        ctx.info(&format!("Challenge '{}' starting up", self.name));
        Ok(())
    }

    async fn on_ready(&self, ctx: &ChallengeContext) -> Result<()> {
        ctx.info(&format!("Challenge '{}' ready", self.name));
        Ok(())
    }

    async fn on_epoch_start(&self, ctx: &ChallengeContext, epoch: u64) -> Result<()> {
        ctx.info(&format!("Epoch {} started", epoch));
        Ok(())
    }

    async fn on_epoch_end(&self, ctx: &ChallengeContext, epoch: u64) -> Result<()> {
        ctx.info(&format!("Epoch {} ended", epoch));
        Ok(())
    }
}

impl EvaluationResult {
    pub fn with_reason(mut self, reason: String) -> Self {
        self.logs = Some(reason);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChallengeDatabase;
    use platform_core::Keypair;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_simple_challenge() {
        let challenge = SimpleTestChallenge::default();

        let dir = tempdir().unwrap();
        let db = Arc::new(ChallengeDatabase::open(dir.path(), challenge.id()).unwrap());
        let validator = Keypair::generate().hotkey();

        let ctx = ChallengeContext::new(challenge.id(), validator, 0, db);

        let agent = AgentInfo::new("test_agent_12345".to_string());
        let result = challenge.evaluate(&ctx, &agent, Value::Null).await.unwrap();

        assert!(result.score > 0.0);
        assert!(result.score <= 1.0);
    }

    #[tokio::test]
    async fn test_weight_calculation() {
        let challenge = SimpleTestChallenge::default();

        let dir = tempdir().unwrap();
        let db = Arc::new(ChallengeDatabase::open(dir.path(), challenge.id()).unwrap());
        let validator = Keypair::generate().hotkey();

        let ctx = ChallengeContext::new(challenge.id(), validator, 0, db.clone());

        // Evaluate some agents
        for i in 0..3 {
            let agent = AgentInfo::new(format!("agent_{}", i));
            let job_ctx = ctx.clone().with_job_id(uuid::Uuid::new_v4());
            let result = challenge
                .evaluate(&job_ctx, &agent, Value::Null)
                .await
                .unwrap();
            db.save_result(&result).unwrap();
        }

        // Calculate weights
        let weights = challenge.calculate_weights(&ctx).await.unwrap();

        assert_eq!(weights.len(), 3);

        // Weights should sum to ~1.0
        let total: f64 = weights.iter().map(|w| w.weight).sum();
        assert!((total - 1.0).abs() < 0.01);
    }
}
