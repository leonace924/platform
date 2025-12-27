//! Evaluations API handlers

use crate::db::queries;
use crate::models::*;
use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use std::sync::Arc;
use tracing::info;

pub async fn submit_evaluation(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubmitEvaluationRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let evaluation = queries::create_evaluation(&state.db, &req)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "success": false, "error": e.to_string() })),
            )
        })?;

    // Update leaderboard
    let _ = queries::update_leaderboard(&state.db, &req.agent_hash).await;

    // Broadcast evaluation event
    state
        .broadcast_event(WsEvent::EvaluationComplete(EvaluationEvent {
            submission_id: req.submission_id.clone(),
            agent_hash: req.agent_hash.clone(),
            validator_hotkey: req.validator_hotkey.clone(),
            score: req.score,
            tasks_passed: req.tasks_passed,
            tasks_total: req.tasks_total,
        }))
        .await;

    info!(
        "Evaluation submitted: {} by {} (score: {:.2})",
        req.agent_hash, req.validator_hotkey, req.score
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "evaluation_id": evaluation.id,
    })))
}

pub async fn get_evaluations(
    State(state): State<Arc<AppState>>,
    Path(agent_hash): Path<String>,
) -> Result<Json<Vec<Evaluation>>, StatusCode> {
    let evaluations = queries::get_evaluations_for_agent(&state.db, &agent_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(evaluations))
}
