//! Commit-Reveal scheme for weight submissions
//!
//! Prevents validators from seeing others' weights before committing their own.

use crate::{FinalizedWeights, WeightCommitment, WeightReveal};
use parking_lot::RwLock;
use platform_challenge_sdk::{weights, ChallengeId, WeightAssignment};
use platform_core::Hotkey;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Commit-reveal state for a single epoch
pub struct CommitRevealState {
    epoch: u64,
    challenge_id: ChallengeId,

    /// Commitments by validator
    commitments: HashMap<Hotkey, WeightCommitment>,

    /// Reveals by validator (after reveal phase)
    reveals: HashMap<Hotkey, WeightReveal>,

    /// Validators who committed but didn't reveal (penalized)
    missing_reveals: Vec<Hotkey>,

    /// Validators whose reveal didn't match commitment
    mismatched_reveals: Vec<Hotkey>,
}

impl CommitRevealState {
    pub fn new(epoch: u64, challenge_id: ChallengeId) -> Self {
        Self {
            epoch,
            challenge_id,
            commitments: HashMap::new(),
            reveals: HashMap::new(),
            missing_reveals: Vec::new(),
            mismatched_reveals: Vec::new(),
        }
    }

    /// Submit a commitment
    pub fn submit_commitment(
        &mut self,
        commitment: WeightCommitment,
    ) -> Result<(), CommitRevealError> {
        if commitment.epoch != self.epoch {
            return Err(CommitRevealError::WrongEpoch {
                expected: self.epoch,
                got: commitment.epoch,
            });
        }

        if commitment.challenge_id != self.challenge_id {
            return Err(CommitRevealError::WrongChallenge);
        }

        if self.commitments.contains_key(&commitment.validator) {
            return Err(CommitRevealError::AlreadyCommitted);
        }

        debug!(
            "Validator {:?} committed weights for epoch {}",
            commitment.validator, self.epoch
        );

        self.commitments
            .insert(commitment.validator.clone(), commitment);
        Ok(())
    }

    /// Submit a reveal
    pub fn submit_reveal(&mut self, reveal: WeightReveal) -> Result<(), CommitRevealError> {
        if reveal.epoch != self.epoch {
            return Err(CommitRevealError::WrongEpoch {
                expected: self.epoch,
                got: reveal.epoch,
            });
        }

        // Check that validator committed
        let commitment = self
            .commitments
            .get(&reveal.validator)
            .ok_or(CommitRevealError::NoCommitment)?;

        // Verify reveal matches commitment
        let computed_hash = weights::create_commitment(&reveal.weights, &reveal.secret);
        if computed_hash != commitment.commitment_hash {
            warn!(
                "Validator {:?} reveal doesn't match commitment",
                reveal.validator
            );
            self.mismatched_reveals.push(reveal.validator.clone());
            return Err(CommitRevealError::CommitmentMismatch);
        }

        if self.reveals.contains_key(&reveal.validator) {
            return Err(CommitRevealError::AlreadyRevealed);
        }

        debug!(
            "Validator {:?} revealed weights for epoch {}",
            reveal.validator, self.epoch
        );

        self.reveals.insert(reveal.validator.clone(), reveal);
        Ok(())
    }

    /// Finalize weights after reveal phase
    pub fn finalize(
        &mut self,
        smoothing: f64,
        min_validators: usize,
    ) -> Result<FinalizedWeights, CommitRevealError> {
        // Find validators who committed but didn't reveal
        for validator in self.commitments.keys() {
            if !self.reveals.contains_key(validator) && !self.mismatched_reveals.contains(validator)
            {
                self.missing_reveals.push(validator.clone());
            }
        }

        if !self.missing_reveals.is_empty() {
            warn!(
                "Epoch {}: {} validators committed but didn't reveal",
                self.epoch,
                self.missing_reveals.len()
            );
        }

        // Collect valid submissions
        let submissions: Vec<Vec<WeightAssignment>> =
            self.reveals.values().map(|r| r.weights.clone()).collect();

        if submissions.len() < min_validators {
            return Err(CommitRevealError::InsufficientValidators {
                required: min_validators,
                got: submissions.len(),
            });
        }

        // All validators read from shared chain DB, so submissions should be identical
        // Just take the first one and normalize
        let aggregated = submissions
            .into_iter()
            .next()
            .map(|w| weights::normalize_weights(w))
            .unwrap_or_default();

        let participating: Vec<Hotkey> = self.reveals.keys().cloned().collect();
        let mut excluded = self.missing_reveals.clone();
        excluded.extend(self.mismatched_reveals.clone());

        info!(
            "Epoch {} finalized: {} validators, {} excluded, {} agents",
            self.epoch,
            participating.len(),
            excluded.len(),
            aggregated.len()
        );

        Ok(FinalizedWeights {
            challenge_id: self.challenge_id,
            epoch: self.epoch,
            weights: aggregated,
            participating_validators: participating,
            excluded_validators: excluded,
            smoothing_applied: 0.0,
            finalized_at: chrono::Utc::now(),
        })
    }

    /// Get number of commitments
    pub fn commitment_count(&self) -> usize {
        self.commitments.len()
    }

    /// Get number of reveals
    pub fn reveal_count(&self) -> usize {
        self.reveals.len()
    }

    /// Check if validator has committed
    pub fn has_committed(&self, validator: &Hotkey) -> bool {
        self.commitments.contains_key(validator)
    }

    /// Check if validator has revealed
    pub fn has_revealed(&self, validator: &Hotkey) -> bool {
        self.reveals.contains_key(validator)
    }
}

/// Errors for commit-reveal
#[derive(Debug, thiserror::Error)]
pub enum CommitRevealError {
    #[error("Wrong epoch: expected {expected}, got {got}")]
    WrongEpoch { expected: u64, got: u64 },

    #[error("Wrong challenge")]
    WrongChallenge,

    #[error("Already committed")]
    AlreadyCommitted,

    #[error("Already revealed")]
    AlreadyRevealed,

    #[error("No commitment found")]
    NoCommitment,

    #[error("Reveal doesn't match commitment")]
    CommitmentMismatch,

    #[error("Insufficient validators: required {required}, got {got}")]
    InsufficientValidators { required: usize, got: usize },

    #[error("Aggregation failed: {0}")]
    AggregationFailed(String),
}

/// Manager for multiple challenges' commit-reveal states
pub struct CommitRevealManager {
    states: RwLock<HashMap<(u64, ChallengeId), CommitRevealState>>,
}

impl CommitRevealManager {
    pub fn new() -> Self {
        Self {
            states: RwLock::new(HashMap::new()),
        }
    }

    /// Get or create state for an epoch/challenge
    pub fn get_or_create(
        &self,
        epoch: u64,
        challenge_id: ChallengeId,
    ) -> parking_lot::RwLockWriteGuard<'_, HashMap<(u64, ChallengeId), CommitRevealState>> {
        let mut states = self.states.write();
        let key = (epoch, challenge_id);

        states
            .entry(key)
            .or_insert_with(|| CommitRevealState::new(epoch, challenge_id));

        states
    }

    /// Submit commitment
    pub fn commit(
        &self,
        epoch: u64,
        challenge_id: ChallengeId,
        commitment: WeightCommitment,
    ) -> Result<(), CommitRevealError> {
        let mut states = self.states.write();
        let key = (epoch, challenge_id);

        let state = states
            .entry(key)
            .or_insert_with(|| CommitRevealState::new(epoch, challenge_id));

        state.submit_commitment(commitment)
    }

    /// Submit reveal
    pub fn reveal(
        &self,
        epoch: u64,
        challenge_id: ChallengeId,
        reveal: WeightReveal,
    ) -> Result<(), CommitRevealError> {
        let mut states = self.states.write();
        let key = (epoch, challenge_id);

        let state = states
            .get_mut(&key)
            .ok_or(CommitRevealError::NoCommitment)?;

        state.submit_reveal(reveal)
    }

    /// Finalize epoch
    pub fn finalize(
        &self,
        epoch: u64,
        challenge_id: ChallengeId,
        smoothing: f64,
        min_validators: usize,
    ) -> Result<FinalizedWeights, CommitRevealError> {
        let mut states = self.states.write();
        let key = (epoch, challenge_id);

        let state = states
            .get_mut(&key)
            .ok_or(CommitRevealError::InsufficientValidators {
                required: min_validators,
                got: 0,
            })?;

        state.finalize(smoothing, min_validators)
    }

    /// Clean up old epochs
    pub fn cleanup_old_epochs(&self, current_epoch: u64, keep_epochs: u64) {
        let mut states = self.states.write();
        let cutoff = current_epoch.saturating_sub(keep_epochs);

        states.retain(|(epoch, _), _| *epoch >= cutoff);
    }
}

impl Default for CommitRevealManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_core::Keypair;

    fn create_test_commitment(
        validator: &Keypair,
        epoch: u64,
        challenge_id: ChallengeId,
    ) -> (WeightCommitment, WeightReveal) {
        let weights = vec![
            WeightAssignment::new("agent1".to_string(), 0.6),
            WeightAssignment::new("agent2".to_string(), 0.4),
        ];
        let secret = b"test_secret".to_vec();
        let hash = weights::create_commitment(&weights, &secret);

        let commitment = WeightCommitment {
            validator: validator.hotkey(),
            challenge_id,
            epoch,
            commitment_hash: hash,
            timestamp: chrono::Utc::now(),
        };

        let reveal = WeightReveal {
            validator: validator.hotkey(),
            challenge_id,
            epoch,
            weights,
            secret,
            timestamp: chrono::Utc::now(),
        };

        (commitment, reveal)
    }

    #[test]
    fn test_commit_reveal_flow() {
        let challenge_id = ChallengeId::new();
        let mut state = CommitRevealState::new(0, challenge_id);

        let validator = Keypair::generate();
        let (commitment, reveal) = create_test_commitment(&validator, 0, challenge_id);

        // Submit commitment
        state.submit_commitment(commitment).unwrap();
        assert!(state.has_committed(&validator.hotkey()));

        // Submit reveal
        state.submit_reveal(reveal).unwrap();
        assert!(state.has_revealed(&validator.hotkey()));
    }

    #[test]
    fn test_commitment_mismatch() {
        let challenge_id = ChallengeId::new();
        let mut state = CommitRevealState::new(0, challenge_id);

        let validator = Keypair::generate();
        let (commitment, mut reveal) = create_test_commitment(&validator, 0, challenge_id);

        state.submit_commitment(commitment).unwrap();

        // Modify reveal to not match commitment
        reveal.secret = b"wrong_secret".to_vec();

        let result = state.submit_reveal(reveal);
        assert!(matches!(result, Err(CommitRevealError::CommitmentMismatch)));
    }
}
