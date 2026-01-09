//! Observability - Sentry Integration
//!
//! Provides Sentry error tracking (enabled via SENTRY_DSN env var)

use tracing::info;

/// Initialize Sentry if SENTRY_DSN is set
pub fn init_sentry() -> Option<sentry::ClientInitGuard> {
    let dsn = std::env::var("SENTRY_DSN").ok()?;

    if dsn.is_empty() {
        info!("Sentry DSN is empty, error tracking disabled");
        return None;
    }

    let guard = sentry::init((
        dsn,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            environment: std::env::var("ENVIRONMENT").ok().map(|s| s.into()),
            traces_sample_rate: 0.1, // 10% of transactions
            ..Default::default()
        },
    ));

    info!("Sentry initialized for error tracking");
    Some(guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_sentry_no_dsn() {
        // Without SENTRY_DSN environment variable
        std::env::remove_var("SENTRY_DSN");
        let guard = init_sentry();
        assert!(guard.is_none());
    }

    #[test]
    fn test_init_sentry_empty_dsn() {
        // With empty SENTRY_DSN
        std::env::set_var("SENTRY_DSN", "");
        let _guard = init_sentry();
        assert!(_guard.is_none());
        std::env::remove_var("SENTRY_DSN");
    }
}
