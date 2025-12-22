//! Weight Calculator
//!
//! Converts challenge leaderboard scores to Bittensor weights.
//! Pure pass-through of challenge weights - no manipulation.
//! Unused weight automatically goes to UID 0 (burn address).

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Maximum weight value for Bittensor (u16 max)
pub const MAX_WEIGHT: u16 = 65535;

/// UID 0 is the burn address - receives all unused weight
pub const BURN_UID: u16 = 0;

/// Weight calculator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightCalculatorConfig {
    /// Minimum score to receive any weight (default: 0.0 = no threshold)
    pub min_score_threshold: f64,
    /// Temperature for softmax (higher = more distributed weights)
    pub temperature: f64,
    /// Whether to use softmax or linear normalization
    pub use_softmax: bool,
    /// Maximum weight any single UID can receive (as fraction) - DISABLED (set to 1.0)
    /// NOTE: Weight cap removed - challenges receive pure weights based on emission %
    pub max_weight_fraction: f64,
    /// Mechanism ID for this challenge
    pub mechanism_id: u8,
}

impl Default for WeightCalculatorConfig {
    fn default() -> Self {
        Self {
            min_score_threshold: 0.0,
            temperature: 1.0,
            use_softmax: false,       // Use simple linear normalization
            max_weight_fraction: 1.0, // No cap - pure weights
            mechanism_id: 0,
        }
    }
}

/// Weight calculator
pub struct WeightCalculator {
    config: WeightCalculatorConfig,
}

/// Score entry for a miner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerScore {
    /// Miner UID
    pub uid: u16,
    /// Miner hotkey
    pub hotkey: String,
    /// Score (0.0 - 1.0)
    pub score: f64,
    /// Agent hash that produced this score
    pub agent_hash: String,
    /// Number of tasks completed
    pub tasks_completed: u32,
    /// Total cost in USD
    pub cost_usd: f64,
}

/// Calculated weight
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalculatedWeight {
    /// Miner UID
    pub uid: u16,
    /// Raw weight (u16)
    pub weight: u16,
    /// Normalized weight (0.0 - 1.0)
    pub normalized: f64,
    /// Original score
    pub score: f64,
}

/// Weight calculation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightCalculationResult {
    /// Calculated weights
    pub weights: Vec<CalculatedWeight>,
    /// Mechanism ID
    pub mechanism_id: u8,
    /// Epoch
    pub epoch: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Total miners scored
    pub total_miners: u32,
    /// Miners receiving weight
    pub miners_with_weight: u32,
}

impl WeightCalculator {
    pub fn new(config: WeightCalculatorConfig) -> Self {
        Self { config }
    }

    /// Calculate weights from scores
    pub fn calculate(&self, scores: &[MinerScore], epoch: u64) -> WeightCalculationResult {
        // Filter scores above threshold
        let valid_scores: Vec<_> = scores
            .iter()
            .filter(|s| s.score >= self.config.min_score_threshold)
            .collect();

        if valid_scores.is_empty() {
            warn!("No valid scores to calculate weights from");
            return WeightCalculationResult {
                weights: vec![],
                mechanism_id: self.config.mechanism_id,
                epoch,
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
                total_miners: scores.len() as u32,
                miners_with_weight: 0,
            };
        }

        // Calculate normalized weights
        let normalized = if self.config.use_softmax {
            self.softmax_normalize(&valid_scores)
        } else {
            self.linear_normalize(&valid_scores)
        };

        // Apply max weight cap
        let capped = self.apply_weight_cap(normalized);

        // Convert to u16 weights
        let weights: Vec<CalculatedWeight> = capped
            .into_iter()
            .map(|(uid, norm, score)| {
                let weight = (norm * MAX_WEIGHT as f64).round() as u16;
                CalculatedWeight {
                    uid,
                    weight,
                    normalized: norm,
                    score,
                }
            })
            .collect();

        info!(
            "Calculated weights for {} miners (epoch {})",
            weights.len(),
            epoch
        );

        WeightCalculationResult {
            miners_with_weight: weights.iter().filter(|w| w.weight > 0).count() as u32,
            weights,
            mechanism_id: self.config.mechanism_id,
            epoch,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            total_miners: scores.len() as u32,
        }
    }

    /// Softmax normalization
    fn softmax_normalize(&self, scores: &[&MinerScore]) -> Vec<(u16, f64, f64)> {
        let temp = self.config.temperature;

        // Calculate exp(score/temp) for each
        let exp_scores: Vec<f64> = scores.iter().map(|s| (s.score / temp).exp()).collect();

        let sum: f64 = exp_scores.iter().sum();

        scores
            .iter()
            .zip(exp_scores.iter())
            .map(|(s, &exp)| (s.uid, exp / sum, s.score))
            .collect()
    }

    /// Linear normalization
    fn linear_normalize(&self, scores: &[&MinerScore]) -> Vec<(u16, f64, f64)> {
        let sum: f64 = scores.iter().map(|s| s.score).sum();

        if sum == 0.0 {
            // Equal weights if all scores are 0
            let equal = 1.0 / scores.len() as f64;
            return scores.iter().map(|s| (s.uid, equal, s.score)).collect();
        }

        scores
            .iter()
            .map(|s| (s.uid, s.score / sum, s.score))
            .collect()
    }

    /// Apply weight cap (DISABLED - pure pass-through)
    ///
    /// NOTE: Weight caps have been removed for simpler, more transparent weight distribution.
    /// Challenges receive weights purely based on their emission percentage.
    /// Unused weight is sent to UID 0 (burn address).
    fn apply_weight_cap(&self, weights: Vec<(u16, f64, f64)>) -> Vec<(u16, f64, f64)> {
        // No cap applied - return weights as-is
        // Normalization already done in normalize_scores()
        weights
    }

    /// Convert to Bittensor weight format (uid, weight pairs)
    pub fn to_bittensor_format(&self, result: &WeightCalculationResult) -> Vec<(u16, u16)> {
        result
            .weights
            .iter()
            .filter(|w| w.weight > 0)
            .map(|w| (w.uid, w.weight))
            .collect()
    }

    /// Create commit hash for commit-reveal
    pub fn create_commit(&self, weights: &[(u16, u16)], salt: &[u8; 32]) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();

        // Hash weights
        for (uid, weight) in weights {
            hasher.update(uid.to_le_bytes());
            hasher.update(weight.to_le_bytes());
        }

        // Add salt
        hasher.update(salt);

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

/// Commit-reveal state for weight submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRevealState {
    /// Committed hash
    pub commit_hash: [u8; 32],
    /// Salt used for commit
    pub salt: [u8; 32],
    /// The actual weights
    pub weights: Vec<(u16, u16)>,
    /// Commit block
    pub commit_block: u64,
    /// Whether committed
    pub committed: bool,
    /// Whether revealed
    pub revealed: bool,
    /// Epoch
    pub epoch: u64,
}

impl CommitRevealState {
    pub fn new(weights: Vec<(u16, u16)>, epoch: u64) -> Self {
        use rand::RngCore;

        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);

        let calculator = WeightCalculator::new(WeightCalculatorConfig::default());
        let commit_hash = calculator.create_commit(&weights, &salt);

        Self {
            commit_hash,
            salt,
            weights,
            commit_block: 0,
            committed: false,
            revealed: false,
            epoch,
        }
    }

    /// Verify a reveal matches the commit
    pub fn verify_reveal(&self, weights: &[(u16, u16)], salt: &[u8; 32]) -> bool {
        let calculator = WeightCalculator::new(WeightCalculatorConfig::default());
        let computed = calculator.create_commit(weights, salt);
        computed == self.commit_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scores() -> Vec<MinerScore> {
        vec![
            MinerScore {
                uid: 1,
                hotkey: "hotkey1".to_string(),
                score: 0.8,
                agent_hash: "hash1".to_string(),
                tasks_completed: 10,
                cost_usd: 0.5,
            },
            MinerScore {
                uid: 2,
                hotkey: "hotkey2".to_string(),
                score: 0.6,
                agent_hash: "hash2".to_string(),
                tasks_completed: 10,
                cost_usd: 0.3,
            },
            MinerScore {
                uid: 3,
                hotkey: "hotkey3".to_string(),
                score: 0.4,
                agent_hash: "hash3".to_string(),
                tasks_completed: 10,
                cost_usd: 0.2,
            },
        ]
    }

    #[test]
    fn test_linear_normalization() {
        let config = WeightCalculatorConfig {
            use_softmax: false,
            ..Default::default()
        };
        let calc = WeightCalculator::new(config);
        let scores = make_scores();

        let result = calc.calculate(&scores, 1);

        // Sum of normalized weights should be ~1.0
        let sum: f64 = result.weights.iter().map(|w| w.normalized).sum();
        assert!((sum - 1.0).abs() < 0.001);

        // Higher scores should have higher weights
        let w1 = result.weights.iter().find(|w| w.uid == 1).unwrap();
        let w2 = result.weights.iter().find(|w| w.uid == 2).unwrap();
        assert!(w1.weight > w2.weight);
    }

    #[test]
    fn test_softmax_normalization() {
        let config = WeightCalculatorConfig {
            use_softmax: true,
            temperature: 1.0,
            ..Default::default()
        };
        let calc = WeightCalculator::new(config);
        let scores = make_scores();

        let result = calc.calculate(&scores, 1);

        let sum: f64 = result.weights.iter().map(|w| w.normalized).sum();
        assert!((sum - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_no_weight_cap() {
        // Weight caps are DISABLED - pure pass-through
        let config = WeightCalculatorConfig {
            use_softmax: false,
            max_weight_fraction: 1.0, // No cap (default)
            ..Default::default()
        };
        let calc = WeightCalculator::new(config);

        // One score dominates - should get proportional weight
        let scores = vec![
            MinerScore {
                uid: 1,
                hotkey: "h1".to_string(),
                score: 0.9,
                agent_hash: "a1".to_string(),
                tasks_completed: 10,
                cost_usd: 0.5,
            },
            MinerScore {
                uid: 2,
                hotkey: "h2".to_string(),
                score: 0.1,
                agent_hash: "a2".to_string(),
                tasks_completed: 10,
                cost_usd: 0.1,
            },
        ];

        let result = calc.calculate(&scores, 1);

        // With pure pass-through, weights should be proportional to scores
        // Score 0.9 / 1.0 = 90% weight, Score 0.1 / 1.0 = 10% weight
        let uid1_weight = result.weights.iter().find(|w| w.uid == 1).unwrap();
        let uid2_weight = result.weights.iter().find(|w| w.uid == 2).unwrap();

        assert!(
            uid1_weight.normalized > 0.85,
            "UID 1 should get ~90% weight: {}",
            uid1_weight.normalized
        );
        assert!(
            uid2_weight.normalized < 0.15,
            "UID 2 should get ~10% weight: {}",
            uid2_weight.normalized
        );

        // Verify weights still sum to 1.0
        let sum: f64 = result.weights.iter().map(|w| w.normalized).sum();
        assert!(
            (sum - 1.0).abs() < 0.01,
            "Weights don't sum to 1.0: {}",
            sum
        );
    }

    #[test]
    fn test_commit_reveal() {
        let weights = vec![(1, 1000), (2, 500), (3, 250)];
        let state = CommitRevealState::new(weights.clone(), 1);

        // Verify with correct salt
        assert!(state.verify_reveal(&weights, &state.salt));

        // Verify fails with wrong salt
        let wrong_salt = [0u8; 32];
        assert!(!state.verify_reveal(&weights, &wrong_salt));

        // Verify fails with wrong weights
        let wrong_weights = vec![(1, 1001), (2, 500), (3, 250)];
        assert!(!state.verify_reveal(&wrong_weights, &state.salt));
    }

    #[test]
    fn test_bittensor_format() {
        let config = WeightCalculatorConfig::default();
        let calc = WeightCalculator::new(config);
        let scores = make_scores();

        let result = calc.calculate(&scores, 1);
        let bt_weights = calc.to_bittensor_format(&result);

        assert_eq!(bt_weights.len(), 3);
        for (uid, weight) in bt_weights {
            assert!(uid > 0);
            assert!(weight > 0);
        }
    }
}
