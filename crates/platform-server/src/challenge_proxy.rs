//! Challenge Proxy - Routes requests to challenge Docker container
//!
//! The challenge container exposes its own routes which are proxied through
//! platform-server. This allows challenges to define custom logic while
//! platform-server handles auth, WebSocket broadcasting, and database.

use axum::{
    body::Body,
    extract::{Path, State},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
};
use reqwest::Client;
use std::sync::Arc;
use tracing::{debug, error, warn};

use crate::state::AppState;

pub struct ChallengeProxy {
    pub challenge_id: String,
    pub base_url: String,
    client: Client,
}

impl ChallengeProxy {
    pub fn new(challenge_id: &str, base_url: &str) -> Self {
        Self {
            challenge_id: challenge_id.to_string(),
            base_url: base_url.trim_end_matches('/').to_string(),
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(600)) // 10 minutes for long evaluations
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    pub async fn proxy_request(&self, path: &str, request: Request<Body>) -> Response {
        let url = format!("{}/{}", self.base_url, path.trim_start_matches('/'));

        debug!("Proxying request to challenge: {} -> {}", path, url);

        let method = request.method().clone();
        let headers = request.headers().clone();

        let body_bytes = match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Failed to read request body: {}", e);
                return (StatusCode::BAD_REQUEST, "Failed to read request body").into_response();
            }
        };

        let mut req_builder = self.client.request(method, &url);

        for (key, value) in headers.iter() {
            if key != "host" {
                req_builder = req_builder.header(key, value);
            }
        }

        if !body_bytes.is_empty() {
            req_builder = req_builder.body(body_bytes.to_vec());
        }

        match req_builder.send().await {
            Ok(resp) => {
                let status = resp.status();
                let headers = resp.headers().clone();

                match resp.bytes().await {
                    Ok(body) => {
                        let mut response = Response::builder().status(status);

                        for (key, value) in headers.iter() {
                            response = response.header(key, value);
                        }

                        response
                            .body(Body::from(body))
                            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
                    }
                    Err(e) => {
                        error!("Failed to read response body: {}", e);
                        StatusCode::BAD_GATEWAY.into_response()
                    }
                }
            }
            Err(e) => {
                if e.is_connect() {
                    warn!(
                        "Challenge container not reachable at {}: {}",
                        self.base_url, e
                    );
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Challenge container not available",
                    )
                        .into_response()
                } else if e.is_timeout() {
                    warn!("Request to challenge container timed out: {}", e);
                    (StatusCode::GATEWAY_TIMEOUT, "Challenge container timeout").into_response()
                } else {
                    error!("Failed to proxy request: {}", e);
                    StatusCode::BAD_GATEWAY.into_response()
                }
            }
        }
    }

    pub async fn health_check(&self) -> bool {
        match self
            .client
            .get(&format!("{}/health", self.base_url))
            .send()
            .await
        {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    /// Call /get_weights on the challenge container (for epoch weight calculation)
    pub async fn get_weights(&self, epoch: u64) -> Result<serde_json::Value, String> {
        let url = format!("{}/get_weights?epoch={}", self.base_url, epoch);

        match self.client.get(&url).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    resp.json().await.map_err(|e| e.to_string())
                } else {
                    Err(format!("Challenge returned status: {}", resp.status()))
                }
            }
            Err(e) => Err(e.to_string()),
        }
    }
}

/// Handler for proxying requests to the challenge container (legacy mode)
pub async fn proxy_handler(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    request: Request<Body>,
) -> Response {
    match &state.challenge_proxy {
        Some(proxy) => proxy.proxy_request(&path, request).await,
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Challenge proxy not configured",
        )
            .into_response(),
    }
}
