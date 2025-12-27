//! Error types for challenges

use thiserror::Error;

/// Result type for challenge operations
pub type Result<T> = std::result::Result<T, ChallengeError>;

/// Challenge errors
#[derive(Error, Debug)]
pub enum ChallengeError {
    // ========== New API errors ==========
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(String),

    // ========== Evaluation errors ==========
    #[error("Evaluation error: {0}")]
    Evaluation(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Timeout")]
    Timeout,

    // ========== Legacy errors (kept for compatibility) ==========
    #[error("Database error: {0}")]
    Database(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Configuration error: {0}")]
    #[deprecated(note = "Use Config variant instead")]
    Configuration(String),

    #[error("Unsupported job type: {0}")]
    UnsupportedJobType(String),

    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    #[error("Challenge not found: {0}")]
    ChallengeNotFound(String),

    #[error("Insufficient validators: required {required}, got {got}")]
    InsufficientValidators { required: usize, got: usize },

    #[error("Epoch error: {0}")]
    Epoch(String),

    #[error("Weight error: {0}")]
    Weight(String),

    #[error("Commitment mismatch")]
    CommitmentMismatch,

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<sled::Error> for ChallengeError {
    fn from(err: sled::Error) -> Self {
        ChallengeError::Database(err.to_string())
    }
}

impl From<bincode::Error> for ChallengeError {
    fn from(err: bincode::Error) -> Self {
        ChallengeError::Serialization(err.to_string())
    }
}

impl From<serde_json::Error> for ChallengeError {
    fn from(err: serde_json::Error) -> Self {
        ChallengeError::Serialization(err.to_string())
    }
}

impl From<std::io::Error> for ChallengeError {
    fn from(err: std::io::Error) -> Self {
        ChallengeError::Internal(err.to_string())
    }
}
