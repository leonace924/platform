//! Consensus state management

use crate::{ConsensusConfig, ConsensusPhase, ConsensusResult, RoundState};
use parking_lot::RwLock;
use platform_core::{Proposal, Vote};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// Manages consensus state across multiple proposals
pub struct ConsensusState {
    /// Active rounds by proposal ID
    rounds: Arc<RwLock<HashMap<Uuid, RoundState>>>,

    /// Completed proposals
    completed: Arc<RwLock<Vec<ConsensusResult>>>,

    /// Configuration
    config: ConsensusConfig,

    /// Number of active validators
    validator_count: Arc<RwLock<usize>>,
}

impl ConsensusState {
    pub fn new(config: ConsensusConfig) -> Self {
        Self {
            rounds: Arc::new(RwLock::new(HashMap::new())),
            completed: Arc::new(RwLock::new(Vec::new())),
            config,
            validator_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Update validator count
    pub fn set_validator_count(&self, count: usize) {
        *self.validator_count.write() = count;
    }

    /// Get the consensus threshold
    pub fn threshold(&self) -> usize {
        let count = *self.validator_count.read();
        ((count as f64) * self.config.threshold).ceil() as usize
    }

    /// Start a new round for a proposal
    pub fn start_round(&self, proposal: Proposal) -> Uuid {
        let id = proposal.id;
        let round = RoundState::new(proposal, self.config.round_timeout_secs);
        self.rounds.write().insert(id, round);
        id
    }

    /// Add a vote to a round
    pub fn add_vote(&self, vote: Vote) -> Option<ConsensusResult> {
        let proposal_id = vote.proposal_id;
        let mut rounds = self.rounds.write();

        let result = if let Some(round) = rounds.get_mut(&proposal_id) {
            round.add_vote(vote);

            let threshold = self.threshold();
            let validator_count = *self.validator_count.read();

            // Check if consensus reached
            if round.has_consensus(threshold) {
                round.phase = ConsensusPhase::Completed;
                Some(ConsensusResult::Approved(Box::new(round.proposal.clone())))
            }
            // Check if rejection is certain
            else if round.is_rejected(validator_count, threshold) {
                round.phase = ConsensusPhase::Failed;
                Some(ConsensusResult::Rejected {
                    proposal_id: round.proposal.id,
                    reason: "Not enough approvals possible".into(),
                })
            } else {
                // Update phase
                if round.approve_count() > 0 {
                    round.phase = ConsensusPhase::Prepare;
                }
                None
            }
        } else {
            None
        };

        // Remove from rounds if we have a result
        if result.is_some() {
            rounds.remove(&proposal_id);
            if let Some(ref r) = result {
                self.completed.write().push(r.clone());
            }
        }

        result
    }

    /// Check for timed out rounds
    pub fn check_timeouts(&self) -> Vec<ConsensusResult> {
        let mut results = Vec::new();
        let mut rounds = self.rounds.write();

        let timed_out: Vec<Uuid> = rounds
            .iter()
            .filter(|(_, r)| r.is_timed_out())
            .map(|(id, _)| *id)
            .collect();

        for id in timed_out {
            if let Some(round) = rounds.remove(&id) {
                let result = ConsensusResult::Rejected {
                    proposal_id: id,
                    reason: "Timeout".into(),
                };
                self.completed.write().push(result.clone());
                results.push(result);
            }
        }

        results
    }

    /// Get round state
    pub fn get_round(&self, proposal_id: &Uuid) -> Option<RoundState> {
        self.rounds.read().get(proposal_id).cloned()
    }

    /// Get all active rounds
    pub fn active_rounds(&self) -> Vec<RoundState> {
        self.rounds.read().values().cloned().collect()
    }

    /// Check if a proposal is pending
    pub fn is_pending(&self, proposal_id: &Uuid) -> bool {
        self.rounds.read().contains_key(proposal_id)
    }

    /// Get completed results
    pub fn completed_results(&self) -> Vec<ConsensusResult> {
        self.completed.read().clone()
    }

    /// Clear completed results
    pub fn clear_completed(&self) {
        self.completed.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_core::{Keypair, ProposalAction};

    #[test]
    fn test_consensus_threshold() {
        let state = ConsensusState::new(ConsensusConfig::default());

        // Default threshold is 33% (0.33)
        // Test with 8 validators: ceil(8 * 0.33) = ceil(2.64) = 3
        state.set_validator_count(8);
        assert_eq!(state.threshold(), 3);

        // Test with 4 validators: ceil(4 * 0.33) = ceil(1.32) = 2
        state.set_validator_count(4);
        assert_eq!(state.threshold(), 2);
    }

    #[test]
    fn test_consensus_flow() {
        let state = ConsensusState::new(ConsensusConfig::default());
        state.set_validator_count(4);

        let proposer = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            proposer.hotkey(),
            1,
        );

        let proposal_id = state.start_round(proposal);

        // Add 3 approve votes (threshold is 3)
        for _ in 0..3 {
            let voter = Keypair::generate();
            let vote = Vote::approve(proposal_id, voter.hotkey());
            let result = state.add_vote(vote);

            if let Some(ConsensusResult::Approved(_)) = result {
                return; // Success!
            }
        }

        panic!("Should have reached consensus");
    }

    #[test]
    fn test_rejection() {
        let state = ConsensusState::new(ConsensusConfig::default());
        state.set_validator_count(4);

        let proposer = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            proposer.hotkey(),
            1,
        );

        let proposal_id = state.start_round(proposal);

        // Add 3 reject votes (makes consensus impossible with 50% threshold = 2 votes needed)
        // With 3 rejects, max approves = 1, which is less than threshold of 2
        for _ in 0..3 {
            let voter = Keypair::generate();
            let vote = Vote::reject(proposal_id, voter.hotkey());
            let result = state.add_vote(vote);

            if let Some(ConsensusResult::Rejected { .. }) = result {
                return; // Expected rejection
            }
        }

        panic!("Should have been rejected");
    }

    #[test]
    fn test_completed_results() {
        let state = ConsensusState::new(ConsensusConfig::default());
        state.set_validator_count(4);

        let proposer = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            proposer.hotkey(),
            1,
        );

        let proposal_id = state.start_round(proposal);

        // Add votes to reach consensus
        for _ in 0..3 {
            let voter = Keypair::generate();
            let vote = Vote::approve(proposal_id, voter.hotkey());
            state.add_vote(vote);
        }

        // Check completed results
        let completed = state.completed_results();
        assert_eq!(completed.len(), 1);
        assert!(matches!(completed[0], ConsensusResult::Approved(_)));
    }

    #[test]
    fn test_clear_completed() {
        let state = ConsensusState::new(ConsensusConfig::default());
        state.set_validator_count(4);

        let proposer = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            proposer.hotkey(),
            1,
        );

        let proposal_id = state.start_round(proposal);

        // Add votes to reach consensus
        for _ in 0..3 {
            let voter = Keypair::generate();
            let vote = Vote::approve(proposal_id, voter.hotkey());
            state.add_vote(vote);
        }

        // Verify we have completed results
        assert_eq!(state.completed_results().len(), 1);

        // Clear completed
        state.clear_completed();

        // Verify cleared
        assert_eq!(state.completed_results().len(), 0);
    }

    #[test]
    fn test_get_round() {
        let state = ConsensusState::new(ConsensusConfig::default());

        let proposer = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            proposer.hotkey(),
            1,
        );

        let proposal_id = state.start_round(proposal.clone());

        // Get round
        let round = state.get_round(&proposal_id);
        assert!(round.is_some());
        assert_eq!(round.unwrap().proposal.id, proposal_id);

        // Non-existent round
        let fake_id = uuid::Uuid::new_v4();
        let non_existent = state.get_round(&fake_id);
        assert!(non_existent.is_none());
    }

    #[test]
    fn test_is_pending() {
        let state = ConsensusState::new(ConsensusConfig::default());

        let proposer = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            proposer.hotkey(),
            1,
        );

        let proposal_id = state.start_round(proposal);

        assert!(state.is_pending(&proposal_id));

        let fake_id = uuid::Uuid::new_v4();
        assert!(!state.is_pending(&fake_id));
    }

    #[test]
    fn test_active_rounds() {
        let state = ConsensusState::new(ConsensusConfig::default());

        // Initially empty
        assert_eq!(state.active_rounds().len(), 0);

        let proposer = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            proposer.hotkey(),
            1,
        );

        state.start_round(proposal);

        // Now has one active round
        assert_eq!(state.active_rounds().len(), 1);
    }

    #[test]
    fn test_check_timeouts_with_rounds() {
        let state = ConsensusState::new(ConsensusConfig::default());

        let proposer = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            proposer.hotkey(),
            1,
        );

        state.start_round(proposal);

        // Check timeouts (won't timeout immediately)
        let timeouts = state.check_timeouts();
        assert_eq!(timeouts.len(), 0);
    }

    #[test]
    fn test_add_vote_to_nonexistent_round() {
        let state = ConsensusState::new(ConsensusConfig::default());
        state.set_validator_count(4);

        let fake_id = uuid::Uuid::new_v4();
        let voter = Keypair::generate();
        let vote = Vote::approve(fake_id, voter.hotkey());

        let result = state.add_vote(vote);
        assert!(result.is_none());
    }

    #[test]
    fn test_add_vote_triggers_rejection() {
        let state = ConsensusState::new(ConsensusConfig::default());
        state.set_validator_count(4); // Threshold is ceil(4 * 0.33) = 2

        let proposer = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            proposer.hotkey(),
            1,
        );

        let proposal_id = state.start_round(proposal);

        // Add 3 reject votes - makes consensus impossible
        for _ in 0..3 {
            let voter = Keypair::generate();
            let vote = Vote::reject(proposal_id, voter.hotkey());
            let result = state.add_vote(vote);

            if let Some(ConsensusResult::Rejected { .. }) = result {
                // Successfully triggered rejection
                assert!(!state.is_pending(&proposal_id));
                return;
            }
        }

        // Should have been rejected
        assert!(!state.is_pending(&proposal_id));
    }

    #[test]
    fn test_add_vote_updates_phase() {
        let state = ConsensusState::new(ConsensusConfig::default());
        state.set_validator_count(10);

        let proposer = Keypair::generate();
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            proposer.hotkey(),
            1,
        );

        let proposal_id = state.start_round(proposal);

        // Add one approve vote - should update phase to Prepare
        let voter = Keypair::generate();
        let vote = Vote::approve(proposal_id, voter.hotkey());
        state.add_vote(vote);

        // Round should still be active and phase should be updated to Prepare
        let round = state.get_round(&proposal_id);
        assert!(round.is_some());
        assert_eq!(round.unwrap().phase, ConsensusPhase::Prepare);
    }
}
