//! Leaderboard API handlers

use crate::db::queries;
use crate::models::*;
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct LeaderboardQuery {
    pub limit: Option<usize>,
}

pub async fn get_leaderboard(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LeaderboardQuery>,
) -> Result<Json<Vec<LeaderboardEntry>>, StatusCode> {
    let limit = query.limit.unwrap_or(100);
    let entries = queries::get_leaderboard(&state.db, limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(entries))
}

pub async fn get_agent_rank(
    State(state): State<Arc<AppState>>,
    Path(agent_hash): Path<String>,
) -> Result<Json<LeaderboardEntry>, StatusCode> {
    let entry = queries::get_leaderboard_entry(&state.db, &agent_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(entry))
}
