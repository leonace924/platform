//! Challenges API handlers

use crate::db::queries;
use crate::models::*;
use crate::state::AppState;
use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;

pub async fn get_network_state(
    State(state): State<Arc<AppState>>,
) -> Result<Json<NetworkStateEvent>, StatusCode> {
    let current_epoch = queries::get_current_epoch(&state.db).await.unwrap_or(0);
    // Use cached current_block from state (updated by block sync)
    // Fall back to database if not set
    let current_block = {
        let cached = state.get_current_block();
        if cached > 0 {
            cached
        } else {
            queries::get_network_state(&state.db, "current_block")
                .await
                .unwrap_or(None)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0u64)
        }
    };
    // Use cached tempo from state (fetched from Bittensor)
    let tempo = state.get_tempo();
    let total_stake = queries::get_total_stake(&state.db).await.unwrap_or(0);
    let validators = queries::get_validators(&state.db).await.unwrap_or_default();
    let pending = queries::get_pending_submissions(&state.db)
        .await
        .unwrap_or_default();

    Ok(Json(NetworkStateEvent {
        current_epoch,
        current_block,
        tempo,
        total_stake,
        active_validators: validators.len() as u32,
        pending_submissions: pending.len() as u32,
    }))
}
