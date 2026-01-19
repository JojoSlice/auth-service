use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions},
    ConnectOptions,
};
use std::{str::FromStr, time::Duration};
use tracing::log::LevelFilter;

use crate::config::DatabaseConfig;
use crate::error::Result;

pub type DbPool = SqlitePool;

pub async fn create_pool(config: &DatabaseConfig) -> Result<DbPool> {
    let connect_options = SqliteConnectOptions::from_str(&config.url)?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(config.connection_timeout_seconds))
        .log_statements(LevelFilter::Debug)
        .log_slow_statements(LevelFilter::Warn, Duration::from_secs(1));

    let pool = SqlitePoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(Duration::from_secs(config.connection_timeout_seconds))
        .connect_with(connect_options)
        .await?;

    tracing::info!("Database pool created successfully");

    Ok(pool)
}

pub async fn run_migrations(pool: &DbPool) -> Result<()> {
    tracing::info!("Running database migrations...");

    sqlx::migrate!("./migrations").run(pool).await?;

    tracing::info!("Database migrations completed successfully");
    Ok(())
}
