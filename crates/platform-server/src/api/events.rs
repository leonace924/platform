//! Challenge Events API
//!
//! Allows challenges to broadcast custom events to validators via WebSocket.
//! Secured with shared secret to prevent unauthorized broadcasts.

use crate::models::{ChallengeCustomEvent, WsEvent};
use crate::state::AppState;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

/// Shared secret for challenge event broadcasts (set via BROADCAST_SECRET env var)
/// Challenges must include this in X-Broadcast-Secret header
fn get_broadcast_secret() -> Option<String> {
    std::env::var("BROADCAST_SECRET").ok()
}

#[derive(Debug, Deserialize)]
pub struct BroadcastEventRequest {
    /// Challenge ID (must match a registered challenge)
    pub challenge_id: String,
    /// Event name (e.g., "new_submission", "evaluation_needed")
    pub event_name: String,
    /// Event payload - challenge-specific JSON data
    pub payload: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct BroadcastEventResponse {
    pub success: bool,
    pub connections_notified: usize,
    pub error: Option<String>,
}

/// POST /api/v1/events/broadcast - Broadcast a custom challenge event
///
/// Called by challenge containers to notify validators of events.
/// Validators filter events by challenge_id to receive only relevant ones.
///
/// Requires X-Broadcast-Secret header matching BROADCAST_SECRET env var.
pub async fn broadcast_event(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BroadcastEventRequest>,
) -> Result<Json<BroadcastEventResponse>, (StatusCode, String)> {
    // Verify broadcast secret
    if let Some(expected_secret) = get_broadcast_secret() {
        let provided_secret = headers
            .get("X-Broadcast-Secret")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if provided_secret != expected_secret {
            warn!(
                "Unauthorized broadcast attempt for challenge: {}",
                req.challenge_id
            );
            return Err((StatusCode::UNAUTHORIZED, "Invalid broadcast secret".into()));
        }
    }
    // Create the custom event
    let event = ChallengeCustomEvent {
        challenge_id: req.challenge_id.clone(),
        event_name: req.event_name.clone(),
        payload: req.payload,
        timestamp: chrono::Utc::now().timestamp(),
    };

    // Get connection count before broadcast
    let connections = state.broadcaster.connection_count();

    // Broadcast to all connected clients
    state.broadcaster.broadcast(WsEvent::ChallengeEvent(event));

    info!(
        "Broadcast challenge event: {}:{} to {} connections",
        req.challenge_id, req.event_name, connections
    );

    Ok(Json(BroadcastEventResponse {
        success: true,
        connections_notified: connections,
        error: None,
    }))
}
