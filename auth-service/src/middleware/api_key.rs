use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::Arc;

use crate::db::ApiKeyRepository;
use crate::models::ValidatedApiKey;
use crate::security::ApiKeyService;

pub const API_KEY_HEADER: &str = "x-api-key";

#[derive(Clone)]
pub struct ApiKeyState {
    pub repository: Arc<ApiKeyRepository>,
    pub service: Arc<ApiKeyService>,
}

pub async fn api_key_middleware(
    State(state): State<ApiKeyState>,
    mut request: Request,
    next: Next,
) -> Response {
    let api_key = match request.headers().get(API_KEY_HEADER) {
        Some(value) => match value.to_str() {
            Ok(key) => key.to_string(),
            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "Unauthorized",
                        "error_description": "Invalid API key format"
                    })),
                )
                    .into_response();
            }
        },
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "Unauthorized",
                    "error_description": "Missing API key"
                })),
            )
                .into_response();
        }
    };

    let prefix = ApiKeyService::get_prefix(&api_key);
    let candidates = match state.repository.find_by_prefix(&prefix).await {
        Ok(keys) => keys,
        Err(e) => {
            tracing::error!(error = %e, "Error fetching API keys");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Internal Server Error",
                    "error_description": "Failed to validate API key"
                })),
            )
                .into_response();
        }
    };

    let mut validated_key = None;
    for candidate in candidates {
        if !candidate.is_active {
            continue;
        }
        if candidate.is_expired() {
            continue;
        }
        if state.service.verify_api_key(&api_key, &candidate.key_hash) {
            validated_key = Some(candidate);
            break;
        }
    }

    let Some(key) = validated_key else {
        tracing::warn!(prefix = %prefix, "Invalid API key attempted");
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Unauthorized",
                "error_description": "Invalid or expired API key"
            })),
        )
            .into_response();
    };

    if let Err(e) = state.repository.update_last_used(&key.id).await {
        tracing::error!(error = %e, "Failed to update API key last used timestamp");
    }

    let validated: ValidatedApiKey = key.into();
    request.extensions_mut().insert(validated);

    next.run(request).await
}

pub async fn optional_api_key_middleware(
    State(state): State<ApiKeyState>,
    mut request: Request,
    next: Next,
) -> Response {
    if let Some(value) = request.headers().get(API_KEY_HEADER) {
        if let Ok(api_key) = value.to_str() {
            let prefix = ApiKeyService::get_prefix(api_key);
            if let Ok(candidates) = state.repository.find_by_prefix(&prefix).await {
                for candidate in candidates {
                    if candidate.is_active
                        && !candidate.is_expired()
                        && state.service.verify_api_key(api_key, &candidate.key_hash)
                    {
                        let _ = state.repository.update_last_used(&candidate.id).await;
                        let validated: ValidatedApiKey = candidate.into();
                        request.extensions_mut().insert(validated);
                        break;
                    }
                }
            }
        }
    }

    next.run(request).await
}
