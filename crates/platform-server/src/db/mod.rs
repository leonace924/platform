//! Database module for Platform Server
//!
//! Supports two modes:
//! 1. Single database for server: platform_server (dynamic orchestration)
//! 2. Per-challenge databases: platform_{challenge_id} (legacy)

pub mod queries;
pub mod schema;

use anyhow::{anyhow, Result};
use deadpool_postgres::{Config, Pool, Runtime};
use tokio_postgres::NoTls;
use tracing::info;

pub type DbPool = Pool;

/// Initialize centralized server database
/// Creates platform_server database if it doesn't exist
pub async fn init_db(base_url: &str) -> Result<DbPool> {
    let db_name = "platform_server";

    // Strip trailing database name if present (e.g., /postgres)
    let base_url = base_url
        .trim_end_matches(|c: char| c != '/')
        .trim_end_matches('/');

    // Connect to postgres database to create server database if needed
    let admin_pool = create_pool(&format!("{}/postgres", base_url)).await?;
    let admin_client = admin_pool.get().await?;

    // Check if database exists
    let row = admin_client
        .query_opt("SELECT 1 FROM pg_database WHERE datname = $1", &[&db_name])
        .await?;

    if row.is_none() {
        admin_client
            .execute(&format!("CREATE DATABASE {}", db_name), &[])
            .await?;
        info!("Created database: {}", db_name);
    }

    // Connect to server database
    let server_url = format!("{}/{}", base_url, db_name);
    let pool = create_pool(&server_url).await?;

    // Run migrations
    let client = pool.get().await?;
    schema::run_migrations(&client, "server").await?;

    info!("Server database initialized: {}", db_name);
    Ok(pool)
}

/// Initialize database for a specific challenge (legacy mode)
/// Creates database if it doesn't exist, then runs migrations
pub async fn init_challenge_db(base_url: &str, challenge_id: &str) -> Result<DbPool> {
    // Validate challenge_id (alphanumeric and hyphens only)
    if !challenge_id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(anyhow!(
            "Invalid challenge_id: must be alphanumeric with hyphens/underscores only"
        ));
    }

    let db_name = format!("platform_{}", challenge_id.replace('-', "_"));

    // Strip trailing database name if present
    let base_url = base_url
        .trim_end_matches(|c: char| c != '/')
        .trim_end_matches('/');

    // Connect to postgres database to create challenge database if needed
    let admin_pool = create_pool(&format!("{}/postgres", base_url)).await?;
    let admin_client = admin_pool.get().await?;

    // Check if database exists
    let row = admin_client
        .query_opt("SELECT 1 FROM pg_database WHERE datname = $1", &[&db_name])
        .await?;

    if row.is_none() {
        // Create database for this challenge
        admin_client
            .execute(&format!("CREATE DATABASE {}", db_name), &[])
            .await?;
        info!("Created database: {}", db_name);
    }

    // Now connect to the challenge-specific database
    let challenge_url = format!("{}/{}", base_url, db_name);
    let pool = create_pool(&challenge_url).await?;

    // Run migrations
    let client = pool.get().await?;
    schema::run_migrations(&client, challenge_id).await?;

    info!(
        "Challenge database initialized: {} ({})",
        challenge_id, db_name
    );
    Ok(pool)
}

async fn create_pool(database_url: &str) -> Result<DbPool> {
    let mut cfg = Config::new();
    cfg.url = Some(database_url.to_string());
    let pool = cfg.create_pool(Some(Runtime::Tokio1), NoTls)?;
    Ok(pool)
}

/// Get base database URL from environment
pub fn get_base_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432".to_string())
        .trim_end_matches(|c: char| c != '/')
        .trim_end_matches('/')
        .to_string()
}
