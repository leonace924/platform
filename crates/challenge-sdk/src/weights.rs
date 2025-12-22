//! Weight utilities for challenges
//!
//! Provides functions for:
//! - Normalizing weights to sum to 1.0
//! - Commit-reveal scheme for weight submission
//!
//! Note: Weight calculation is done by the challenge itself using the shared
//! chain DB. All validators read from the same DB and will get the same result.
//! The challenge uses stake-weighted scoring when calculating final weights.

use crate::WeightAssignment;
use sha2::{Digest, Sha256};

/// Create a commitment hash for weight reveal verification
///
/// Uses SHA256 hash of sorted weights and secret for commit-reveal scheme.
pub fn create_commitment(weights: &[WeightAssignment], secret: &[u8]) -> String {
    let mut hasher = Sha256::new();

    // Hash weights in deterministic order (by hotkey)
    let mut sorted_weights = weights.to_vec();
    sorted_weights.sort_by(|a, b| a.hotkey.cmp(&b.hotkey));

    for w in &sorted_weights {
        hasher.update(w.hotkey.as_bytes());
        hasher.update(w.weight.to_le_bytes());
    }

    // Add secret for privacy
    hasher.update(secret);

    hex::encode(hasher.finalize())
}

/// Normalize weights to sum to 1.0
pub fn normalize_weights(mut weights: Vec<WeightAssignment>) -> Vec<WeightAssignment> {
    let total: f64 = weights.iter().map(|w| w.weight).sum();

    if total > 0.0 {
        for w in &mut weights {
            w.weight /= total;
        }
    }

    weights
}

/// Calculate weights from evaluation scores
///
/// Converts raw scores to normalized weights.
/// The hotkey is the miner's SS58 address.
pub fn scores_to_weights(scores: &[(String, f64)]) -> Vec<WeightAssignment> {
    if scores.is_empty() {
        return vec![];
    }

    let total: f64 = scores.iter().map(|(_, s)| s).sum();

    if total <= 0.0 {
        return vec![];
    }

    scores
        .iter()
        .map(|(hotkey, score)| WeightAssignment::new(hotkey.clone(), score / total))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_weights() {
        // Note: WeightAssignment::new clamps values to 0-1
        // So we use raw values that are already in range
        let weights = vec![
            WeightAssignment {
                hotkey: "hotkey1".to_string(),
                weight: 0.4,
            },
            WeightAssignment {
                hotkey: "hotkey2".to_string(),
                weight: 0.6,
            },
        ];

        let normalized = normalize_weights(weights);

        // Find by hotkey since order may vary
        let h1 = normalized.iter().find(|w| w.hotkey == "hotkey1").unwrap();
        let h2 = normalized.iter().find(|w| w.hotkey == "hotkey2").unwrap();

        assert!((h1.weight - 0.4).abs() < 0.001);
        assert!((h2.weight - 0.6).abs() < 0.001);
    }

    #[test]
    fn test_scores_to_weights() {
        let scores = vec![("hotkey1".to_string(), 0.8), ("hotkey2".to_string(), 0.2)];

        let weights = scores_to_weights(&scores);

        assert_eq!(weights.len(), 2);
        assert!((weights[0].weight - 0.8).abs() < 0.001);
        assert!((weights[1].weight - 0.2).abs() < 0.001);
    }

    #[test]
    fn test_empty_scores() {
        let scores: Vec<(String, f64)> = vec![];
        let weights = scores_to_weights(&scores);
        assert!(weights.is_empty());
    }
}
