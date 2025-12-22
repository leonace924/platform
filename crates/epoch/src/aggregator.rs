//! Weight aggregator
//!
//! Aggregates weights from multiple validators and challenges.

use crate::{AgentEmission, EmissionDistribution, EpochConfig, FinalizedWeights};
use platform_challenge_sdk::{ChallengeId, ChallengeMetadata};
use platform_core::Hotkey;
use std::collections::HashMap;
use tracing::{info, warn};

/// Aggregates weights across all challenges for emission distribution
pub struct WeightAggregator {
    config: EpochConfig,
}

impl WeightAggregator {
    pub fn new(config: EpochConfig) -> Self {
        Self { config }
    }

    /// Calculate emissions for an epoch
    ///
    /// Takes finalized weights from all challenges and distributes emissions
    /// according to each challenge's emission weight.
    pub fn calculate_emissions(
        &self,
        epoch: u64,
        total_emission: u64,
        challenges: &[ChallengeMetadata],
        finalized_weights: &HashMap<ChallengeId, FinalizedWeights>,
    ) -> EmissionDistribution {
        let mut distributions = Vec::new();

        // Normalize challenge emission weights
        let total_challenge_weight: f64 = challenges
            .iter()
            .filter(|c| c.is_active)
            .map(|c| c.emission_weight)
            .sum();

        if total_challenge_weight == 0.0 {
            warn!("No active challenges with emission weight");
            return EmissionDistribution {
                epoch,
                total_emission,
                distributions: vec![],
                timestamp: chrono::Utc::now(),
            };
        }

        for challenge in challenges {
            if !challenge.is_active {
                continue;
            }

            // Get finalized weights for this challenge
            let weights = match finalized_weights.get(&challenge.id) {
                Some(fw) => &fw.weights,
                None => {
                    warn!("No finalized weights for challenge {:?}", challenge.id);
                    continue;
                }
            };

            // Calculate challenge's share of total emission
            let challenge_share = challenge.emission_weight / total_challenge_weight;
            let challenge_emission = (total_emission as f64 * challenge_share) as u64;

            info!(
                "Challenge {} gets {}% ({} units) of emission",
                challenge.name,
                challenge_share * 100.0,
                challenge_emission
            );

            // Distribute to miners based on weights
            for weight in weights {
                let miner_emission = (challenge_emission as f64 * weight.weight) as u64;

                distributions.push(AgentEmission {
                    hotkey: weight.hotkey.clone(),
                    weight: weight.weight,
                    emission: miner_emission,
                    challenge_id: challenge.id,
                });
            }
        }

        // Merge emissions for same agent across challenges
        let merged = self.merge_agent_emissions(distributions);

        info!(
            "Epoch {} emission distribution: {} agents, {} total",
            epoch,
            merged.len(),
            total_emission
        );

        EmissionDistribution {
            epoch,
            total_emission,
            distributions: merged,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Merge emissions for same miner across multiple challenges
    fn merge_agent_emissions(&self, distributions: Vec<AgentEmission>) -> Vec<AgentEmission> {
        let mut by_miner: HashMap<String, Vec<AgentEmission>> = HashMap::new();

        for dist in distributions {
            by_miner.entry(dist.hotkey.clone()).or_default().push(dist);
        }

        by_miner
            .into_iter()
            .map(|(hotkey, emissions)| {
                let total_emission: u64 = emissions.iter().map(|e| e.emission).sum();
                let total_weight: f64 = emissions.iter().map(|e| e.weight).sum();

                // Use the first challenge_id (or could aggregate differently)
                let challenge_id = emissions
                    .first()
                    .map(|e| e.challenge_id)
                    .unwrap_or_else(ChallengeId::new);

                AgentEmission {
                    hotkey,
                    weight: total_weight / emissions.len() as f64,
                    emission: total_emission,
                    challenge_id,
                }
            })
            .collect()
    }

    /// Detect validators with suspicious weight patterns
    pub fn detect_suspicious_validators(
        &self,
        finalized_weights: &[FinalizedWeights],
    ) -> Vec<SuspiciousValidator> {
        let mut suspicious = Vec::new();

        for fw in finalized_weights {
            // Check for validators who were excluded
            for validator in &fw.excluded_validators {
                suspicious.push(SuspiciousValidator {
                    hotkey: validator.clone(),
                    reason: SuspicionReason::ExcludedFromConsensus,
                    challenge_id: fw.challenge_id,
                    epoch: fw.epoch,
                });
            }
        }

        suspicious
    }

    /// Calculate validator performance metrics
    pub fn validator_metrics(
        &self,
        validator: &Hotkey,
        history: &[FinalizedWeights],
    ) -> ValidatorMetrics {
        let mut participated = 0;
        let mut excluded = 0;

        for fw in history {
            if fw.participating_validators.contains(validator) {
                participated += 1;
            } else if fw.excluded_validators.contains(validator) {
                excluded += 1;
            }
        }

        let total = participated + excluded;
        let participation_rate = if total > 0 {
            participated as f64 / total as f64
        } else {
            0.0
        };

        ValidatorMetrics {
            hotkey: validator.clone(),
            epochs_participated: participated,
            epochs_excluded: excluded,
            participation_rate,
        }
    }
}

/// Suspicious validator report
#[derive(Clone, Debug)]
pub struct SuspiciousValidator {
    pub hotkey: Hotkey,
    pub reason: SuspicionReason,
    pub challenge_id: ChallengeId,
    pub epoch: u64,
}

/// Reason for suspicion
#[derive(Clone, Debug)]
pub enum SuspicionReason {
    /// Validator was excluded from consensus
    ExcludedFromConsensus,
    /// Validator's weights deviated significantly
    WeightDeviation { deviation: f64 },
    /// Validator didn't participate
    NoParticipation,
}

/// Validator performance metrics
#[derive(Clone, Debug)]
pub struct ValidatorMetrics {
    pub hotkey: Hotkey,
    pub epochs_participated: usize,
    pub epochs_excluded: usize,
    pub participation_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WeightAssignment;
    use platform_core::Keypair;

    fn create_test_challenge(name: &str, weight: f64) -> ChallengeMetadata {
        ChallengeMetadata {
            id: ChallengeId::new(),
            name: name.to_string(),
            description: "Test".to_string(),
            version: "1.0".to_string(),
            owner: Keypair::generate().hotkey(),
            emission_weight: weight,
            config: platform_challenge_sdk::ChallengeConfig::default(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            is_active: true,
        }
    }

    #[test]
    fn test_emission_distribution() {
        let aggregator = WeightAggregator::new(EpochConfig::default());

        let challenge1 = create_test_challenge("Challenge1", 0.6);
        let challenge2 = create_test_challenge("Challenge2", 0.4);

        let mut finalized = HashMap::new();

        finalized.insert(
            challenge1.id,
            FinalizedWeights {
                challenge_id: challenge1.id,
                epoch: 0,
                weights: vec![
                    WeightAssignment::new("agent1".to_string(), 0.7),
                    WeightAssignment::new("agent2".to_string(), 0.3),
                ],
                participating_validators: vec![],
                excluded_validators: vec![],
                smoothing_applied: 0.3,
                finalized_at: chrono::Utc::now(),
            },
        );

        finalized.insert(
            challenge2.id,
            FinalizedWeights {
                challenge_id: challenge2.id,
                epoch: 0,
                weights: vec![
                    WeightAssignment::new("agent1".to_string(), 0.5),
                    WeightAssignment::new("agent3".to_string(), 0.5),
                ],
                participating_validators: vec![],
                excluded_validators: vec![],
                smoothing_applied: 0.3,
                finalized_at: chrono::Utc::now(),
            },
        );

        let distribution =
            aggregator.calculate_emissions(0, 1000, &[challenge1, challenge2], &finalized);

        assert_eq!(distribution.epoch, 0);
        assert!(!distribution.distributions.is_empty());

        // Total emissions should approximately equal total_emission
        let total: u64 = distribution.distributions.iter().map(|d| d.emission).sum();
        assert!(total <= 1000);
    }
}
