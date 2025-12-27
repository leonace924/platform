//! Validators API handlers

use crate::db::queries;
use crate::models::*;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

pub async fn list_validators(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<Validator>>, StatusCode> {
    let validators = queries::get_validators(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(validators))
}

pub async fn get_validator(
    State(state): State<Arc<AppState>>,
    Path(hotkey): Path<String>,
) -> Result<Json<Validator>, StatusCode> {
    let validator = queries::get_validator(&state.db, &hotkey)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(validator))
}

pub async fn register_validator(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ValidatorRegistration>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    queries::upsert_validator(&state.db, &req.hotkey, req.stake)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "success": false, "error": e.to_string() })),
            )
        })?;

    state
        .broadcast_event(WsEvent::ValidatorJoined(ValidatorEvent {
            hotkey: req.hotkey.clone(),
            stake: req.stake,
        }))
        .await;

    Ok(Json(
        serde_json::json!({ "success": true, "hotkey": req.hotkey }),
    ))
}

#[derive(Debug, Deserialize)]
pub struct HeartbeatRequest {
    pub hotkey: String,
    pub signature: String,
}

pub async fn heartbeat(
    State(state): State<Arc<AppState>>,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    queries::upsert_validator(&state.db, &req.hotkey, 0)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({ "success": true })))
}
