//! PBFT Consensus Engine

use crate::{ConsensusConfig, ConsensusResult, ConsensusState};
use parking_lot::RwLock;
use platform_core::{
    ChainState, Hotkey, Keypair, MiniChainError, NetworkMessage, Proposal, ProposalAction, Result,
    SignedNetworkMessage, SudoAction, Vote,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// PBFT Consensus Engine
pub struct PBFTEngine {
    /// Local keypair
    keypair: Keypair,

    /// Consensus state
    state: ConsensusState,

    /// Chain state reference
    chain_state: Arc<RwLock<ChainState>>,

    /// Outgoing message sender
    message_tx: mpsc::Sender<SignedNetworkMessage>,
}

impl PBFTEngine {
    pub fn new(
        keypair: Keypair,
        chain_state: Arc<RwLock<ChainState>>,
        message_tx: mpsc::Sender<SignedNetworkMessage>,
    ) -> Self {
        let config = ConsensusConfig::default();
        Self {
            keypair,
            state: ConsensusState::new(config),
            chain_state,
            message_tx,
        }
    }

    /// Update validator count from chain state
    pub fn sync_validators(&self) {
        let count = self.chain_state.read().active_validators().len();
        self.state.set_validator_count(count);
    }

    /// Check if we are the sudo key
    pub fn is_sudo(&self) -> bool {
        self.chain_state.read().is_sudo(&self.keypair.hotkey())
    }

    /// Propose a sudo action (only subnet owner)
    pub async fn propose_sudo(&self, action: SudoAction) -> Result<uuid::Uuid> {
        if !self.is_sudo() {
            return Err(MiniChainError::Unauthorized("Not the subnet owner".into()));
        }

        let block_height = self.chain_state.read().block_height;
        let proposal = Proposal::new(
            ProposalAction::Sudo(action),
            self.keypair.hotkey(),
            block_height,
        );

        let proposal_id = self.state.start_round(proposal.clone());

        // Broadcast proposal
        let msg = NetworkMessage::Proposal(proposal);
        let signed = SignedNetworkMessage::new(msg, &self.keypair)?;
        self.message_tx
            .send(signed)
            .await
            .map_err(|e| MiniChainError::Network(e.to_string()))?;

        // Self-vote approve
        self.vote(proposal_id, true).await?;

        info!("Proposed sudo action: {:?}", proposal_id);
        Ok(proposal_id)
    }

    /// Propose a new block
    #[allow(clippy::await_holding_lock)]
    pub async fn propose_block(&self) -> Result<uuid::Uuid> {
        let state = self.chain_state.read();
        let block_height = state.block_height;
        let state_hash = state.state_hash;
        drop(state);

        let proposal = Proposal::new(
            ProposalAction::NewBlock { state_hash },
            self.keypair.hotkey(),
            block_height,
        );

        let proposal_id = self.state.start_round(proposal.clone());

        // Broadcast proposal
        let msg = NetworkMessage::Proposal(proposal);
        let signed = SignedNetworkMessage::new(msg, &self.keypair)?;
        self.message_tx
            .send(signed)
            .await
            .map_err(|e| MiniChainError::Network(e.to_string()))?;

        // Self-vote approve
        self.vote(proposal_id, true).await?;

        debug!("Proposed new block: {:?}", proposal_id);
        Ok(proposal_id)
    }

    /// Handle incoming proposal
    pub async fn handle_proposal(&self, proposal: Proposal, signer: &Hotkey) -> Result<()> {
        // Verify proposer
        if proposal.proposer != *signer {
            return Err(MiniChainError::InvalidSignature);
        }

        // For sudo actions, verify sender is the sudo key
        if let ProposalAction::Sudo(_) = &proposal.action {
            if !self.chain_state.read().is_sudo(signer) {
                warn!("Non-sudo tried to propose sudo action: {:?}", signer);
                return Err(MiniChainError::Unauthorized("Not sudo".into()));
            }
        }

        // Validate proposal
        if !self.validate_proposal(&proposal) {
            warn!("Invalid proposal: {:?}", proposal.id);
            self.vote(proposal.id, false).await?;
            return Ok(());
        }

        // Start round and vote approve
        self.state.start_round(proposal.clone());
        self.vote(proposal.id, true).await?;

        Ok(())
    }

    /// Vote on a proposal
    async fn vote(&self, proposal_id: uuid::Uuid, approve: bool) -> Result<()> {
        let vote = if approve {
            Vote::approve(proposal_id, self.keypair.hotkey())
        } else {
            Vote::reject(proposal_id, self.keypair.hotkey())
        };

        // Add local vote
        if let Some(result) = self.state.add_vote(vote.clone()) {
            self.handle_consensus_result(result).await?;
        }

        // Broadcast vote
        let msg = NetworkMessage::Vote(vote);
        let signed = SignedNetworkMessage::new(msg, &self.keypair)?;
        self.message_tx
            .send(signed)
            .await
            .map_err(|e| MiniChainError::Network(e.to_string()))?;

        Ok(())
    }

    /// Handle incoming vote
    pub async fn handle_vote(&self, vote: Vote, signer: &Hotkey) -> Result<()> {
        // Verify voter
        if vote.voter != *signer {
            return Err(MiniChainError::InvalidSignature);
        }

        // Verify voter is a validator
        if self.chain_state.read().get_validator(signer).is_none() {
            warn!("Non-validator tried to vote: {:?}", signer);
            return Ok(());
        }

        // Add vote
        if let Some(result) = self.state.add_vote(vote) {
            self.handle_consensus_result(result).await?;
        }

        Ok(())
    }

    /// Handle consensus result
    async fn handle_consensus_result(&self, result: ConsensusResult) -> Result<()> {
        match result {
            ConsensusResult::Approved(proposal) => {
                info!("Consensus reached for proposal: {:?}", proposal.id);
                self.apply_proposal(*proposal).await?;
            }
            ConsensusResult::Rejected {
                proposal_id,
                reason,
            } => {
                warn!("Proposal rejected: {:?} - {}", proposal_id, reason);
            }
            ConsensusResult::Pending => {}
        }
        Ok(())
    }

    /// Apply an approved proposal
    async fn apply_proposal(&self, proposal: Proposal) -> Result<()> {
        let mut state = self.chain_state.write();

        match proposal.action {
            ProposalAction::Sudo(action) => {
                self.apply_sudo_action(&mut state, action)?;
            }
            ProposalAction::NewBlock { state_hash } => {
                if state.state_hash == state_hash {
                    state.increment_block();
                    info!("New block: {}", state.block_height);
                }
            }
            ProposalAction::JobCompletion {
                job_id,
                result,
                validator,
            } => {
                info!(
                    "Job {} completed by {:?} with score {:?}",
                    job_id, validator, result
                );
            }
        }

        Ok(())
    }

    /// Apply a sudo action
    fn apply_sudo_action(&self, state: &mut ChainState, action: SudoAction) -> Result<()> {
        match action {
            SudoAction::UpdateConfig { config } => {
                state.config = config;
                info!("Config updated");
            }
            SudoAction::AddChallenge { config } => {
                // Store challenge config in state
                state
                    .challenge_configs
                    .insert(config.challenge_id, config.clone());
                info!(
                    "Challenge added: {} ({:?})",
                    config.name, config.challenge_id
                );
            }
            SudoAction::UpdateChallenge { config } => {
                state
                    .challenge_configs
                    .insert(config.challenge_id, config.clone());
                info!(
                    "Challenge updated: {} ({:?})",
                    config.name, config.challenge_id
                );
            }
            SudoAction::RemoveChallenge { id } => {
                state.challenge_configs.remove(&id);
                state.remove_challenge(&id);
                info!("Challenge removed: {:?}", id);
            }
            SudoAction::RefreshChallenges { challenge_id } => {
                // RefreshChallenges is handled by the orchestrator, not state
                // Just log it here
                match challenge_id {
                    Some(id) => info!("Challenge refresh requested: {:?}", id),
                    None => info!("All challenges refresh requested"),
                }
            }
            SudoAction::SetRequiredVersion {
                min_version,
                recommended_version,
                docker_image,
                mandatory,
                deadline_block,
                release_notes,
            } => {
                state.required_version = Some(platform_core::RequiredVersion {
                    min_version: min_version.clone(),
                    recommended_version: recommended_version.clone(),
                    docker_image: docker_image.clone(),
                    mandatory,
                    deadline_block,
                });
                info!(
                    "Required version set: {} (mandatory: {})",
                    min_version, mandatory
                );
            }
            SudoAction::AddValidator { info } => {
                state.add_validator(info)?;
                info!("Validator added");
            }
            SudoAction::RemoveValidator { hotkey } => {
                state.remove_validator(&hotkey);
                info!("Validator removed: {:?}", hotkey);
            }
            SudoAction::EmergencyPause { reason } => {
                warn!("EMERGENCY PAUSE: {}", reason);
            }
            SudoAction::Resume => {
                info!("Network resumed");
            }
            SudoAction::ForceStateUpdate { state: new_state } => {
                *state = new_state;
                warn!("Force state update applied");
            }
            SudoAction::SetChallengeWeight {
                challenge_id,
                mechanism_id,
                weight_ratio,
            } => {
                let allocation = platform_core::ChallengeWeightAllocation::new(
                    challenge_id,
                    mechanism_id,
                    weight_ratio,
                );
                state.challenge_weights.insert(challenge_id, allocation);
                info!(
                    "Challenge weight set: {:?} on mechanism {} = {:.2}%",
                    challenge_id,
                    mechanism_id,
                    weight_ratio * 100.0
                );
            }
            SudoAction::SetMechanismBurnRate {
                mechanism_id,
                burn_rate,
            } => {
                let config = state
                    .mechanism_configs
                    .entry(mechanism_id)
                    .or_insert_with(|| platform_core::MechanismWeightConfig::new(mechanism_id));
                config.base_burn_rate = burn_rate.clamp(0.0, 1.0);
                info!(
                    "Mechanism {} burn rate set to {:.2}%",
                    mechanism_id,
                    burn_rate * 100.0
                );
            }
            SudoAction::SetMechanismConfig {
                mechanism_id,
                config,
            } => {
                state.mechanism_configs.insert(mechanism_id, config.clone());
                info!(
                    "Mechanism {} config updated: burn={:.2}%, cap={:.2}%",
                    mechanism_id,
                    config.base_burn_rate * 100.0,
                    config.max_weight_cap * 100.0
                );
            }
        }

        state.update_hash();
        Ok(())
    }

    /// Validate a proposal
    fn validate_proposal(&self, proposal: &Proposal) -> bool {
        let state = self.chain_state.read();

        // Check block height is current or next
        if proposal.block_height > state.block_height + 1 {
            return false;
        }

        // Proposal-specific validation
        match &proposal.action {
            ProposalAction::Sudo(action) => {
                // Sudo must come from sudo key
                if !state.is_sudo(&proposal.proposer) {
                    return false;
                }
                self.validate_sudo_action(&state, action)
            }
            ProposalAction::NewBlock { .. } => true,
            ProposalAction::JobCompletion { .. } => true,
        }
    }

    /// Validate a sudo action
    fn validate_sudo_action(&self, _state: &ChainState, action: &SudoAction) -> bool {
        match action {
            SudoAction::AddChallenge { config } => {
                // Full validation including Docker image whitelist
                match config.validate() {
                    Ok(()) => {
                        info!(
                            "Challenge config validated: {} ({})",
                            config.name, config.docker_image
                        );
                        true
                    }
                    Err(reason) => {
                        warn!("Challenge config rejected: {}", reason);
                        false
                    }
                }
            }
            SudoAction::UpdateChallenge { config } => {
                // Validate updated config including Docker image whitelist
                match config.validate() {
                    Ok(()) => {
                        info!(
                            "Challenge update validated: {} ({})",
                            config.name, config.docker_image
                        );
                        true
                    }
                    Err(reason) => {
                        warn!("Challenge update rejected: {}", reason);
                        false
                    }
                }
            }
            _ => true,
        }
    }

    /// Check for timeouts and handle them
    pub async fn check_timeouts(&self) -> Result<()> {
        let results = self.state.check_timeouts();
        for result in results {
            self.handle_consensus_result(result).await?;
        }
        Ok(())
    }

    /// Get consensus state for monitoring
    pub fn status(&self) -> ConsensusStatus {
        ConsensusStatus {
            active_rounds: self.state.active_rounds().len(),
            validator_count: self.chain_state.read().validators.len(),
            threshold: self.state.threshold(),
        }
    }
}

/// Consensus status for monitoring
#[derive(Debug, Clone)]
pub struct ConsensusStatus {
    pub active_rounds: usize,
    pub validator_count: usize,
    pub threshold: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_core::{ChallengeConfig, NetworkConfig, Stake, ValidatorInfo};
    use tokio::sync::mpsc;

    fn create_test_engine() -> (PBFTEngine, mpsc::Receiver<SignedNetworkMessage>) {
        let keypair = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            keypair.hotkey(),
            NetworkConfig::default(),
        )));
        let (tx, rx) = mpsc::channel(100);

        let engine = PBFTEngine::new(keypair, state, tx);
        (engine, rx)
    }

    #[tokio::test]
    async fn test_sudo_proposal() {
        let (engine, mut rx) = create_test_engine();

        // Add some validators
        {
            let mut state = engine.chain_state.write();
            for _ in 0..4 {
                let kp = Keypair::generate();
                let info = ValidatorInfo::new(kp.hotkey(), Stake::new(10_000_000_000));
                state.add_validator(info).unwrap();
            }
        }
        engine.sync_validators();

        // Propose sudo action
        let action = SudoAction::UpdateConfig {
            config: NetworkConfig::default(),
        };
        let result = engine.propose_sudo(action).await;
        assert!(result.is_ok());

        // Should have broadcast proposal and vote
        let msg1 = rx.recv().await.unwrap();
        let msg2 = rx.recv().await.unwrap();

        assert!(matches!(msg1.message, NetworkMessage::Proposal(_)));
        assert!(matches!(msg2.message, NetworkMessage::Vote(_)));
    }

    #[tokio::test]
    async fn test_handle_proposal_valid_sudo() {
        let (engine, _rx) = create_test_engine();
        let sudo_key = engine.keypair.hotkey();

        let action = SudoAction::UpdateConfig {
            config: NetworkConfig::default(),
        };
        let proposal = Proposal::new(ProposalAction::Sudo(action), sudo_key.clone(), 0);

        let result = engine.handle_proposal(proposal, &sudo_key).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_proposal_wrong_signer() {
        let (engine, _rx) = create_test_engine();
        let other_key = Keypair::generate().hotkey();

        let action = SudoAction::UpdateConfig {
            config: NetworkConfig::default(),
        };
        let proposal = Proposal::new(ProposalAction::Sudo(action), other_key.clone(), 0);

        // Proposal signed by different key should fail
        let result = engine
            .handle_proposal(proposal, &engine.keypair.hotkey())
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_proposal_non_sudo_action() {
        let (engine, _rx) = create_test_engine();
        let non_sudo = Keypair::generate();

        // Add non-sudo as validator
        {
            let mut state = engine.chain_state.write();
            let info = ValidatorInfo::new(non_sudo.hotkey(), Stake::new(10_000_000_000));
            state.add_validator(info).unwrap();
        }

        let action = SudoAction::UpdateConfig {
            config: NetworkConfig::default(),
        };
        let proposal = Proposal::new(ProposalAction::Sudo(action), non_sudo.hotkey(), 0);

        // Non-sudo proposing sudo action should fail
        let result = engine.handle_proposal(proposal, &non_sudo.hotkey()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_proposal_invalid_challenge_config() {
        let (engine, _rx) = create_test_engine();
        let sudo_key = engine.keypair.hotkey();

        // Create challenge with invalid config (empty name)
        let config = platform_core::ChallengeContainerConfig::new("", "", 1, 0.5);

        let action = SudoAction::AddChallenge { config };
        let proposal = Proposal::new(ProposalAction::Sudo(action), sudo_key.clone(), 0);

        let result = engine.handle_proposal(proposal, &sudo_key).await;
        // Should succeed but vote NO internally
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_vote_from_non_validator() {
        let (engine, _rx) = create_test_engine();
        let non_validator = Keypair::generate();

        let proposal_id = uuid::Uuid::new_v4();
        let vote = Vote::approve(proposal_id, non_validator.hotkey());

        let result = engine.handle_vote(vote, &non_validator.hotkey()).await;
        // Should succeed but be ignored
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_apply_proposal_new_block() {
        let (engine, _rx) = create_test_engine();

        let state_hash = {
            let state = engine.chain_state.read();
            state.state_hash
        };

        let proposal = Proposal::new(
            ProposalAction::NewBlock { state_hash },
            engine.keypair.hotkey(),
            0,
        );

        let result = engine.apply_proposal(proposal).await;
        assert!(result.is_ok());

        // Block should have incremented
        let block = engine.chain_state.read().block_height;
        assert_eq!(block, 1);
    }

    #[tokio::test]
    async fn test_apply_proposal_job_completion() {
        let (engine, _rx) = create_test_engine();

        let job_id = uuid::Uuid::new_v4();
        let validator = engine.keypair.hotkey();

        let proposal = Proposal::new(
            ProposalAction::JobCompletion {
                job_id,
                result: platform_core::Score::new(0.85, 1.0),
                validator,
            },
            engine.keypair.hotkey(),
            0,
        );

        let result = engine.apply_proposal(proposal).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_apply_sudo_action_all_variants() {
        let (engine, _rx) = create_test_engine();
        let challenge_id = platform_core::ChallengeId::new();

        // Test SetChallengeWeight
        let action = SudoAction::SetChallengeWeight {
            challenge_id,
            mechanism_id: 1,
            weight_ratio: 0.5,
        };
        let mut state = engine.chain_state.write();
        assert!(engine.apply_sudo_action(&mut state, action).is_ok());
        assert!(state.challenge_weights.contains_key(&challenge_id));
        drop(state);

        // Test SetMechanismBurnRate
        let action = SudoAction::SetMechanismBurnRate {
            mechanism_id: 1,
            burn_rate: 0.2,
        };
        let mut state = engine.chain_state.write();
        assert!(engine.apply_sudo_action(&mut state, action).is_ok());
        drop(state);

        // Test SetMechanismConfig
        let action = SudoAction::SetMechanismConfig {
            mechanism_id: 2,
            config: platform_core::MechanismWeightConfig::new(2),
        };
        let mut state = engine.chain_state.write();
        assert!(engine.apply_sudo_action(&mut state, action).is_ok());
        drop(state);

        // Test EmergencyPause
        let action = SudoAction::EmergencyPause {
            reason: "Test".to_string(),
        };
        let mut state = engine.chain_state.write();
        assert!(engine.apply_sudo_action(&mut state, action).is_ok());
        drop(state);

        // Test Resume
        let action = SudoAction::Resume;
        let mut state = engine.chain_state.write();
        assert!(engine.apply_sudo_action(&mut state, action).is_ok());
        drop(state);

        // Test ForceStateUpdate
        let new_state = ChainState::new(Hotkey([99u8; 32]), NetworkConfig::default());
        let action = SudoAction::ForceStateUpdate {
            state: new_state.clone(),
        };
        let mut state = engine.chain_state.write();
        assert!(engine.apply_sudo_action(&mut state, action).is_ok());
        assert_eq!(state.sudo_key, Hotkey([99u8; 32]));
    }

    #[tokio::test]
    async fn test_validate_sudo_action_add_challenge() {
        let (engine, _rx) = create_test_engine();
        let state = engine.chain_state.read();

        // Valid challenge config
        let config = platform_core::ChallengeContainerConfig::new(
            "ValidChallenge",
            "ghcr.io/platformnetwork/valid:latest",
            1,
            0.5,
        );
        let action = SudoAction::AddChallenge { config };
        assert!(engine.validate_sudo_action(&state, &action));

        // Invalid challenge config (empty name)
        let invalid_config = platform_core::ChallengeContainerConfig::new("", "", 1, 0.5);
        let action = SudoAction::AddChallenge {
            config: invalid_config,
        };
        assert!(!engine.validate_sudo_action(&state, &action));
    }

    #[tokio::test]
    async fn test_validate_sudo_action_update_challenge() {
        let (engine, _rx) = create_test_engine();
        let state = engine.chain_state.read();

        // Valid update
        let config = platform_core::ChallengeContainerConfig::new(
            "ValidChallenge",
            "ghcr.io/platformnetwork/valid:latest",
            1,
            0.5,
        );
        let action = SudoAction::UpdateChallenge { config };
        assert!(engine.validate_sudo_action(&state, &action));

        // Invalid update (empty name)
        let invalid_config = platform_core::ChallengeContainerConfig::new("", "", 1, 0.5);
        let action = SudoAction::UpdateChallenge {
            config: invalid_config,
        };
        assert!(!engine.validate_sudo_action(&state, &action));
    }

    #[tokio::test]
    async fn test_validate_sudo_action_other_actions() {
        let (engine, _rx) = create_test_engine();
        let state = engine.chain_state.read();

        // All other sudo actions should validate to true
        let action = SudoAction::UpdateConfig {
            config: NetworkConfig::default(),
        };
        assert!(engine.validate_sudo_action(&state, &action));

        let action = SudoAction::RemoveChallenge {
            id: platform_core::ChallengeId::new(),
        };
        assert!(engine.validate_sudo_action(&state, &action));

        let action = SudoAction::Resume;
        assert!(engine.validate_sudo_action(&state, &action));
    }

    #[tokio::test]
    async fn test_check_timeouts() {
        let (engine, _rx) = create_test_engine();

        // Start a round with short timeout
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            engine.keypair.hotkey(),
            0,
        );
        engine.state.start_round(proposal);

        // Wait for timeout (ConsensusConfig default is 30 seconds, but we can check immediately)
        // For testing, we can use check_timeouts
        let result = engine.check_timeouts().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_proposal_block_height() {
        let (engine, _rx) = create_test_engine();

        // Proposal with valid block height
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            engine.keypair.hotkey(),
            0,
        );
        assert!(engine.validate_proposal(&proposal));

        // Proposal with too far future block height
        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            engine.keypair.hotkey(),
            100,
        );
        assert!(!engine.validate_proposal(&proposal));
    }

    #[tokio::test]
    async fn test_validate_proposal_sudo_non_sudo_proposer() {
        let (engine, _rx) = create_test_engine();
        let non_sudo = Keypair::generate();

        let action = SudoAction::UpdateConfig {
            config: NetworkConfig::default(),
        };
        let proposal = Proposal::new(ProposalAction::Sudo(action), non_sudo.hotkey(), 0);

        assert!(!engine.validate_proposal(&proposal));
    }

    #[tokio::test]
    async fn test_validate_proposal_new_block() {
        let (engine, _rx) = create_test_engine();

        let proposal = Proposal::new(
            ProposalAction::NewBlock {
                state_hash: [0u8; 32],
            },
            engine.keypair.hotkey(),
            0,
        );

        assert!(engine.validate_proposal(&proposal));
    }

    #[tokio::test]
    async fn test_validate_proposal_job_completion() {
        let (engine, _rx) = create_test_engine();

        let proposal = Proposal::new(
            ProposalAction::JobCompletion {
                job_id: uuid::Uuid::new_v4(),
                result: platform_core::Score::new(0.9, 1.0),
                validator: engine.keypair.hotkey(),
            },
            engine.keypair.hotkey(),
            0,
        );

        assert!(engine.validate_proposal(&proposal));
    }

    #[tokio::test]
    async fn test_consensus_status() {
        let (engine, _rx) = create_test_engine();

        // Add validators
        {
            let mut state = engine.chain_state.write();
            for _ in 0..5 {
                let kp = Keypair::generate();
                let info = ValidatorInfo::new(kp.hotkey(), Stake::new(10_000_000_000));
                state.add_validator(info).unwrap();
            }
        }
        engine.sync_validators();

        let status = engine.status();
        assert_eq!(status.validator_count, 5);
        assert_eq!(status.threshold, 2); // ceil(5 * 0.33) = 2
    }

    #[tokio::test]
    async fn test_propose_block_flow() {
        let (engine, mut rx) = create_test_engine();

        // Add validators
        {
            let mut state = engine.chain_state.write();
            for _ in 0..3 {
                let kp = Keypair::generate();
                let info = ValidatorInfo::new(kp.hotkey(), Stake::new(10_000_000_000));
                state.add_validator(info).unwrap();
            }
        }
        engine.sync_validators();

        let result = engine.propose_block().await;
        assert!(result.is_ok());

        // Should broadcast proposal and vote
        let _proposal_msg = rx.recv().await;
        let _vote_msg = rx.recv().await;
    }

    #[tokio::test]
    async fn test_handle_consensus_result_rejected() {
        let (engine, _rx) = create_test_engine();

        let proposal_id = uuid::Uuid::new_v4();
        let result = ConsensusResult::Rejected {
            proposal_id,
            reason: "Test rejection".to_string(),
        };

        // Should not panic
        let res = engine.handle_consensus_result(result).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_handle_consensus_result_pending() {
        let (engine, _rx) = create_test_engine();

        let result = ConsensusResult::Pending;

        // Should not panic
        let res = engine.handle_consensus_result(result).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_apply_sudo_action_refresh_challenges_with_id() {
        let (engine, _rx) = create_test_engine();

        let challenge_id = platform_core::ChallengeId::new();
        let action = SudoAction::RefreshChallenges {
            challenge_id: Some(challenge_id),
        };

        let mut state = engine.chain_state.write();
        let result = engine.apply_sudo_action(&mut state, action);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_apply_sudo_action_refresh_challenges_all() {
        let (engine, _rx) = create_test_engine();

        let action = SudoAction::RefreshChallenges { challenge_id: None };

        let mut state = engine.chain_state.write();
        let result = engine.apply_sudo_action(&mut state, action);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_apply_sudo_action_add_validator() {
        let (engine, _rx) = create_test_engine();

        let new_val = ValidatorInfo::new(Hotkey([55u8; 32]), Stake::new(100_000_000_000));
        let action = SudoAction::AddValidator {
            info: new_val.clone(),
        };

        let mut state = engine.chain_state.write();
        let result = engine.apply_sudo_action(&mut state, action);
        assert!(result.is_ok());
        assert!(state.get_validator(&new_val.hotkey).is_some());
    }

    #[tokio::test]
    async fn test_apply_sudo_action_remove_validator() {
        let (engine, _rx) = create_test_engine();

        let hotkey = Hotkey([66u8; 32]);

        // Add then remove
        {
            let mut state = engine.chain_state.write();
            let val = ValidatorInfo::new(hotkey.clone(), Stake::new(100_000_000_000));
            state.add_validator(val).unwrap();
        }

        let action = SudoAction::RemoveValidator {
            hotkey: hotkey.clone(),
        };

        let mut state = engine.chain_state.write();
        let result = engine.apply_sudo_action(&mut state, action);
        assert!(result.is_ok());
        assert!(state.get_validator(&hotkey).is_none());
    }

    #[tokio::test]
    async fn test_apply_sudo_action_set_required_version() {
        let (engine, _rx) = create_test_engine();

        let action = SudoAction::SetRequiredVersion {
            min_version: "2.0.0".to_string(),
            recommended_version: "2.1.0".to_string(),
            docker_image: "validator:2.0.0".to_string(),
            mandatory: true,
            deadline_block: Some(100000),
            release_notes: Some("Important update".to_string()),
        };

        let mut state = engine.chain_state.write();
        let result = engine.apply_sudo_action(&mut state, action);
        assert!(result.is_ok());
        assert!(state.required_version.is_some());
    }

    #[tokio::test]
    async fn test_propose_sudo_non_sudo() {
        let (engine, _rx) = create_test_engine();

        // Create a different keypair (non-sudo)
        let non_sudo = Keypair::generate();
        let state = Arc::new(RwLock::new(ChainState::new(
            engine.keypair.hotkey(),
            NetworkConfig::default(),
        )));
        let (tx, _rx2) = mpsc::channel(100);
        let non_sudo_engine = PBFTEngine::new(non_sudo, state, tx);

        let action = SudoAction::Resume;
        let result = non_sudo_engine.propose_sudo(action).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_vote_wrong_voter() {
        let (engine, _rx) = create_test_engine();

        let proposal_id = uuid::Uuid::new_v4();
        let wrong_hotkey = Keypair::generate().hotkey();
        let vote = Vote::approve(proposal_id, wrong_hotkey.clone());

        // Try to handle vote signed by different key
        let actual_signer = Keypair::generate().hotkey();
        let result = engine.handle_vote(vote, &actual_signer).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_apply_sudo_action_add_challenge_full() {
        let (engine, _rx) = create_test_engine();

        let config = platform_core::ChallengeContainerConfig::new(
            "NewChallenge",
            "ghcr.io/platformnetwork/new:latest",
            2,
            0.3,
        );
        let challenge_id = config.challenge_id;
        let action = SudoAction::AddChallenge {
            config: config.clone(),
        };

        let mut state = engine.chain_state.write();
        let result = engine.apply_sudo_action(&mut state, action);
        assert!(result.is_ok());
        assert!(state.challenge_configs.contains_key(&challenge_id));
        assert_eq!(state.challenge_configs[&challenge_id].name, "NewChallenge");
    }

    #[tokio::test]
    async fn test_apply_sudo_action_update_challenge_full() {
        let (engine, _rx) = create_test_engine();

        let config = platform_core::ChallengeContainerConfig::new(
            "UpdatedChallenge",
            "ghcr.io/platformnetwork/updated:v2",
            3,
            0.4,
        );
        let challenge_id = config.challenge_id;

        let action = SudoAction::UpdateChallenge {
            config: config.clone(),
        };

        let mut state = engine.chain_state.write();
        let result = engine.apply_sudo_action(&mut state, action);
        assert!(result.is_ok());
        assert!(state.challenge_configs.contains_key(&challenge_id));
    }

    #[tokio::test]
    async fn test_apply_sudo_action_remove_challenge_full() {
        let (engine, _rx) = create_test_engine();

        let config = platform_core::ChallengeContainerConfig::new(
            "ToRemove",
            "ghcr.io/platformnetwork/remove:latest",
            1,
            0.2,
        );
        let challenge_id = config.challenge_id;

        // First add the challenge
        {
            let mut state = engine.chain_state.write();
            state.challenge_configs.insert(challenge_id, config);
        }

        let action = SudoAction::RemoveChallenge { id: challenge_id };

        let mut state = engine.chain_state.write();
        let result = engine.apply_sudo_action(&mut state, action);
        assert!(result.is_ok());
        assert!(!state.challenge_configs.contains_key(&challenge_id));
    }
}
