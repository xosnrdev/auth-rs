use std::{net::SocketAddr, time::Duration};

use anyhow::Context;
use axum::{
    error_handling::HandleErrorLayer,
    extract::FromRef,
    http::{HeaderValue, Method, StatusCode},
    routing::{delete, get, patch, post},
    serve, BoxError, Router,
};
use axum_extra::extract::cookie::Key;
use getset::Getters;
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::{net::TcpListener, signal};
use tower::{buffer::BufferLayer, limit::RateLimitLayer, ServiceBuilder};
use tower_http::{cors::CorsLayer, timeout::TimeoutLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    controllers::*,
    utils::{AppConfig, AppResult, DatabaseConfig},
};

//----------------------------------------------------------------------
// Types
//----------------------------------------------------------------------

/// Holds the application state shared across routes.
///
/// ## Fields
/// - `db_pool`: The database connection pool.
/// - `config`: The application configuration.
/// - `key`: A secret key used for cookies.
#[derive(Debug, Clone, Getters)]
pub struct AppState {
    #[getset(get = "pub with_prefix")]
    db_pool: PgPool,
    #[getset(get = "pub with_prefix")]
    config: AppConfig,
    #[getset(get = "pub with_prefix")]
    key: Key,
}

//----------------------------------------------------------------------
// Implementations
//----------------------------------------------------------------------

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.key.to_owned()
    }
}

//----------------------------------------------------------------------
// Methods
//----------------------------------------------------------------------

/// Runs the application server with the provided configuration.
///
/// ## Parameters
/// - `config`: The application configuration.
///
/// ## Returns
/// - `AppResult<()>`: Indicates success or failure of server execution.
pub async fn run_application(config: AppConfig) -> AppResult<()> {
    init_tracing()?;

    let db_pool = create_connection_pool(config.get_database()).await?;

    let app = create_router(db_pool, config.clone());

    let address = SocketAddr::new(
        config.get_server().get_host().parse()?,
        *config.get_server().get_port(),
    );

    let listener = TcpListener::bind(address).await?;

    tracing::info!("Listening on {}:{}", address.ip(), address.port());
    serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("Failed to start server")
}

/// Initializes tracing for logging and diagnostics.
///
/// ## Returns
/// - `AppResult<()>`: Indicates success or failure of tracing initialization.
fn init_tracing() -> AppResult<()> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        format!(
            "{}=info,tower_http=info,axum=debug",
            env!("CARGO_CRATE_NAME")
        )
        .into()
    });

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::UtcTime::rfc_3339());

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .try_init()
        .context("Failed to initialize tracing")
}

/// Creates a database connection pool.
///
/// ## Parameters
/// - `config`: Database configuration.
///
/// ## Returns
/// - `AppResult<PgPool>`: A connection pool for interacting with the database.
pub async fn create_connection_pool(config: &DatabaseConfig) -> AppResult<PgPool> {
    PgPoolOptions::new()
        .max_connections(*config.get_max_connections())
        .min_connections(*config.get_min_connections())
        .acquire_timeout(Duration::from_secs(*config.get_acquire_timeout_secs()))
        .connect_with(config.to_pg_connect_options())
        .await
        .context("Failed to create database connection pool")
}

/// Creates the application router with all routes and middleware configured.
///
/// ## Parameters
/// - `db_pool`: The database connection pool.
/// - `config`: The application configuration.
///
/// ## Returns
/// - `Router`: The configured router.
pub fn create_router(db_pool: PgPool, config: AppConfig) -> Router {
    let key = Key::from(config.get_server().get_cookie_secret().as_bytes());
    let state = AppState {
        db_pool,
        config,
        key,
    };
    let timeout = Duration::from_secs(*state.config.get_server().get_timeout_in_secs());
    let origins: Vec<HeaderValue> = state
        .config
        .get_server()
        .get_origins()
        .split(',')
        .map(str::trim)
        .filter_map(|s| s.parse::<HeaderValue>().ok())
        .collect();

    let cors_layer = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::DELETE,
            Method::PUT,
            Method::PATCH,
        ])
        .allow_credentials(true);

    let trace_layer = TraceLayer::new_for_http();
    let timeout_layer = TimeoutLayer::new(timeout);

    // See https://github.com/tokio-rs/axum/discussions/987
    let rate_limit_layer = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(|err: BoxError| async move {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Unhandled error: {}", err),
            )
        }))
        .layer(BufferLayer::new(1024))
        .layer(RateLimitLayer::new(
            *state.config.get_server().get_rate_limit_burst(),
            Duration::from_secs(*state.config.get_server().get_rate_limit_per_secs()),
        ));

    let users_router = Router::new()
        .route("/register", post(register))
        .route("/", get(get_all_users))
        .route("/me", get(get_me))
        .route("/me", patch(update_me))
        .route("/me", delete(delete_me))
        .without_v07_checks()
        .route("/:id", get(get_user))
        .route("/:id", patch(update_user))
        .route("/:id", delete(delete_user));

    let auth_router = Router::new()
        .route("/login", post(login))
        .route("/logout", post(logout));

    let session_router = Router::new()
        .route("/refresh-cookie", post(refresh_session_by_cookie))
        .route("/refresh", post(refresh_session_by_body))
        .route("/current", patch(revoke_my_session))
        .route("/", patch(revoke_all_sessions))
        .without_v07_checks()
        .route("/:id", patch(revoke_user_session));

    Router::new()
        .route("/", get(health_check))
        .nest("/auth", auth_router)
        .without_v07_checks()
        .nest("/users", users_router)
        .nest("/sessions", session_router)
        .layer(trace_layer)
        .layer(cors_layer)
        .layer(timeout_layer)
        .layer(rate_limit_layer)
        .with_state(state)
}

/// Listens for shutdown signals such as `Ctrl+C` or Unix signals.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C signal handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
