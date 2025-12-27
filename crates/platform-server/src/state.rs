//! Application state

use crate::challenge_proxy::ChallengeProxy;
use crate::db::DbPool;
use crate::models::{AuthSession, TaskLease, WsEvent};
use crate::orchestration::ChallengeManager;
use crate::websocket::events::EventBroadcaster;
use dashmap::DashMap;
use std::sync::Arc;

pub struct AppState {
    pub db: DbPool,
    pub challenge_id: Option<String>,
    pub sessions: DashMap<String, AuthSession>,
    pub broadcaster: Arc<EventBroadcaster>,
    pub owner_hotkey: Option<String>,
    pub challenge_proxy: Option<Arc<ChallengeProxy>>,
    /// Dynamic challenge manager
    pub challenge_manager: Option<Arc<ChallengeManager>>,
    /// Active task leases (task_id -> lease info)
    pub task_leases: DashMap<String, TaskLease>,
}

impl AppState {
    /// Legacy constructor for single challenge mode
    pub fn new(
        db: DbPool,
        challenge_id: String,
        owner_hotkey: Option<String>,
        challenge_proxy: Arc<ChallengeProxy>,
    ) -> Self {
        Self {
            db,
            challenge_id: Some(challenge_id),
            sessions: DashMap::new(),
            broadcaster: Arc::new(EventBroadcaster::new(1000)),
            owner_hotkey,
            challenge_proxy: Some(challenge_proxy),
            challenge_manager: None,
            task_leases: DashMap::new(),
        }
    }

    /// New constructor for dynamic orchestration mode
    pub fn new_dynamic(
        db: DbPool,
        owner_hotkey: Option<String>,
        challenge_manager: Option<Arc<ChallengeManager>>,
    ) -> Self {
        Self {
            db,
            challenge_id: None,
            sessions: DashMap::new(),
            broadcaster: Arc::new(EventBroadcaster::new(1000)),
            owner_hotkey,
            challenge_proxy: None,
            challenge_manager,
            task_leases: DashMap::new(),
        }
    }

    pub async fn broadcast_event(&self, event: WsEvent) {
        self.broadcaster.broadcast(event);
    }

    pub fn is_owner(&self, hotkey: &str) -> bool {
        self.owner_hotkey
            .as_ref()
            .map(|o| o == hotkey)
            .unwrap_or(false)
    }
}
