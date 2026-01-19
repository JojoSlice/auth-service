use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use sqlx::SqlitePool;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub database: String,
}

pub async fn health_check(State(pool): State<SqlitePool>) -> (StatusCode, Json<HealthResponse>) {
    let db_status = match sqlx::query("SELECT 1").fetch_one(&pool).await {
        Ok(_) => "healthy".to_string(),
        Err(e) => {
            tracing::warn!(error = %e, "Database health check failed");
            "unhealthy".to_string()
        }
    };

    let status = if db_status == "healthy" {
        "healthy"
    } else {
        "degraded"
    };

    let response = HealthResponse {
        status: status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        database: db_status,
    };

    let status_code = if status == "healthy" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, Json(response))
}
