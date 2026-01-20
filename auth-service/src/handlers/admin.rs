use axum::{
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};

use crate::db::{ApiKeyRepository, AuditLogRepository, IpFilterRepository};
use crate::error::{AppError, Result};
use crate::middleware::ip_filter::extract_client_ip;
use crate::models::{ApiKey, ApiKeyResponse, AuditLog, FilterType, IpFilter};
use crate::security::ApiKeyService;

#[derive(Clone)]
pub struct AdminHandlerState {
    pub api_key_repository: Arc<ApiKeyRepository>,
    pub api_key_service: Arc<ApiKeyService>,
    pub audit_log_repository: Arc<AuditLogRepository>,
    pub ip_filter_repository: Arc<IpFilterRepository>,
    pub admin_ip_whitelist: Vec<String>,
}

pub async fn admin_ip_check(
    State(state): State<AdminHandlerState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let client_ip = extract_client_ip(&request, &addr);

    let is_allowed = state
        .admin_ip_whitelist
        .iter()
        .any(|allowed| allowed == "*" || allowed == &client_ip || allowed.contains(&client_ip));

    if !is_allowed {
        tracing::warn!(
            ip = %client_ip,
            "Admin endpoint access denied - IP not in whitelist"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "Forbidden",
                "error_description": "Access denied"
            })),
        )
            .into_response();
    }

    next.run(request).await
}

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub client_project: String,
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_minute: i32,
    pub expires_at: Option<String>,
}

fn default_rate_limit() -> i32 {
    60
}

#[derive(Debug, Serialize)]
pub struct CreateApiKeyResponse {
    pub api_key: String,
    pub key_info: ApiKeyResponse,
}

pub async fn create_api_key(
    State(state): State<AdminHandlerState>,
    Json(request): Json<CreateApiKeyRequest>,
) -> Result<Json<CreateApiKeyResponse>> {
    let (key, prefix, hash) = state.api_key_service.generate_api_key();

    let api_key = ApiKey::new(
        hash,
        prefix,
        request.name,
        request.client_project,
        request.allowed_origins,
    )
    .with_rate_limit(request.rate_limit_per_minute);

    let api_key = if let Some(expires_at) = request.expires_at {
        api_key.with_expiration(expires_at)
    } else {
        api_key
    };

    state.api_key_repository.create(&api_key).await?;

    tracing::info!(
        key_id = %api_key.id,
        client_project = %api_key.client_project,
        "API key created"
    );

    Ok(Json(CreateApiKeyResponse {
        api_key: key,
        key_info: api_key.into(),
    }))
}

pub async fn list_api_keys(
    State(state): State<AdminHandlerState>,
) -> Result<Json<Vec<ApiKeyResponse>>> {
    let keys = state.api_key_repository.list_all().await?;
    let responses: Vec<ApiKeyResponse> = keys.into_iter().map(Into::into).collect();
    Ok(Json(responses))
}

pub async fn revoke_api_key(
    State(state): State<AdminHandlerState>,
    Path(key_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    state.api_key_repository.deactivate(&key_id).await?;

    tracing::info!(key_id = %key_id, "API key revoked");

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "API key has been revoked"
    })))
}

pub async fn get_audit_logs(State(state): State<AdminHandlerState>) -> Result<Json<Vec<AuditLog>>> {
    let logs = state.audit_log_repository.find_recent(100).await?;
    Ok(Json(logs))
}

#[derive(Debug, Deserialize)]
pub struct CreateIpFilterRequest {
    pub ip_address: String,
    pub filter_type: String,
    pub reason: Option<String>,
    pub expires_at: Option<String>,
}

pub async fn create_ip_filter(
    State(state): State<AdminHandlerState>,
    Json(request): Json<CreateIpFilterRequest>,
) -> Result<Json<IpFilter>> {
    let filter_type: FilterType = request
        .filter_type
        .parse()
        .map_err(|_| AppError::BadRequest("Invalid filter type".to_string()))?;

    let filter = IpFilter::new(request.ip_address, filter_type, request.reason);

    let filter = if let Some(expires_at) = request.expires_at {
        filter.with_expiration(expires_at)
    } else {
        filter
    };

    state.ip_filter_repository.create(&filter).await?;

    tracing::info!(
        filter_id = %filter.id,
        ip = %filter.ip_address,
        filter_type = %filter.filter_type,
        "IP filter created"
    );

    Ok(Json(filter))
}

pub async fn list_ip_filters(
    State(state): State<AdminHandlerState>,
    Path(filter_type): Path<String>,
) -> Result<Json<Vec<IpFilter>>> {
    let ft: FilterType = filter_type
        .parse()
        .map_err(|_| AppError::BadRequest("Invalid filter type".to_string()))?;

    let filters = state.ip_filter_repository.list_by_type(ft).await?;
    Ok(Json(filters))
}

pub async fn delete_ip_filter(
    State(state): State<AdminHandlerState>,
    Path(filter_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    state.ip_filter_repository.delete(&filter_id).await?;

    tracing::info!(filter_id = %filter_id, "IP filter deleted");

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "IP filter has been deleted"
    })))
}
