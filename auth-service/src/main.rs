use auth_service::{create_router, AppConfig, AppState, Result};
use std::net::SocketAddr;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    let config = AppConfig::load()?;

    init_logging(&config.logging.level, &config.logging.format);

    tracing::info!("Starting Auth Service v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Environment: {}", config.server.environment);

    tracing::info!("Connecting to database...");
    let pool = auth_service::db::create_pool(&config.database).await?;

    tracing::info!("Running database migrations...");
    auth_service::db::run_migrations(&pool).await?;

    let state = AppState::new(pool, config.clone())?;

    let app = create_router(state);

    let addr = SocketAddr::from((
        config
            .server
            .host
            .parse::<std::net::IpAddr>()
            .unwrap_or([0, 0, 0, 0].into()),
        config.server.port,
    ));

    tracing::info!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        auth_service::AppError::InternalServerError(format!("Failed to bind to address: {e}"))
    })?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(|e| auth_service::AppError::InternalServerError(format!("Server error: {e}")))?;

    tracing::info!("Server shutdown complete");

    Ok(())
}

fn init_logging(level: &str, format: &str) {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));

    match format {
        "json" => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        }
        _ => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer().pretty())
                .init();
        }
    }
}

#[allow(clippy::expect_used)]
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
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
        () = ctrl_c => {
            tracing::info!("Received Ctrl+C, starting graceful shutdown...");
        },
        () = terminate => {
            tracing::info!("Received terminate signal, starting graceful shutdown...");
        },
    }
}
