//! Challenges API handlers

use crate::api::auth;
use crate::db::queries;
use crate::models::*;
use crate::state::AppState;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::json;
use std::sync::Arc;
use tracing::info;

pub async fn get_config_current(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ChallengeConfig>, StatusCode> {
    let challenge_id = state.challenge_id.as_deref().unwrap_or("default");
    let config = queries::get_challenge_config(&state.db, challenge_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(config))
}

pub async fn update_config_current(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<UpdateConfigRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_start_matches("Bearer "));

    let session = auth::require_owner(&state, token)
        .map_err(|(code, msg)| (code, Json(json!({ "success": false, "error": msg }))))?;

    let challenge_id = state.challenge_id.as_deref().unwrap_or("default");
    let message = format!(
        "update_config:{}:{}",
        challenge_id,
        serde_json::to_string(&req.config).unwrap_or_default()
    );
    if !auth::verify_signature(&req.owner_hotkey, &message, &req.signature) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "success": false, "error": "Invalid signature" })),
        ));
    }

    if session.hotkey != req.owner_hotkey {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({ "success": false, "error": "Owner hotkey mismatch" })),
        ));
    }

    queries::update_challenge_config(&state.db, challenge_id, &req.config, &req.owner_hotkey)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({ "success": false, "error": format!("Failed to update config: {}", e) }),
                ),
            )
        })?;

    info!("Challenge config updated by {}", req.owner_hotkey);

    for (key, value) in req.config.as_object().unwrap_or(&serde_json::Map::new()) {
        let event = WsEvent::ChallengeUpdated(ChallengeUpdateEvent {
            field: key.clone(),
            old_value: None,
            new_value: value.to_string(),
            updated_by: req.owner_hotkey.clone(),
        });
        state.broadcast_event(event).await;
    }

    Ok(Json(
        json!({ "success": true, "challenge_id": challenge_id }),
    ))
}

pub async fn get_network_state(
    State(state): State<Arc<AppState>>,
) -> Result<Json<NetworkStateEvent>, StatusCode> {
    let current_epoch = queries::get_current_epoch(&state.db).await.unwrap_or(0);
    let current_block = queries::get_network_state(&state.db, "current_block")
        .await
        .unwrap_or(None)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0u64);
    let total_stake = queries::get_total_stake(&state.db).await.unwrap_or(0);
    let validators = queries::get_validators(&state.db).await.unwrap_or_default();
    let pending = queries::get_pending_submissions(&state.db)
        .await
        .unwrap_or_default();

    Ok(Json(NetworkStateEvent {
        current_epoch,
        current_block,
        total_stake,
        active_validators: validators.len() as u32,
        pending_submissions: pending.len() as u32,
    }))
}
