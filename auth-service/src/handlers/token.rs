use axum::{
    extract::State,
    http::{header, HeaderMap},
    Extension, Json,
};
use std::sync::Arc;

use crate::error::Result;
use crate::middleware::{AuthenticatedUser, ClientIp};
use crate::models::{
    DeviceInfo, RefreshTokenRequest, RevokeTokenRequest, TokenPair, ValidateTokenRequest,
    ValidateTokenResponse, ValidatedApiKey,
};
use crate::services::TokenService;

#[derive(Clone)]
pub struct TokenHandlerState {
    pub token_service: Arc<TokenService>,
}

pub async fn refresh_token(
    State(state): State<TokenHandlerState>,
    Extension(api_key): Extension<ValidatedApiKey>,
    Extension(client_ip): Extension<ClientIp>,
    headers: HeaderMap,
    Json(request): Json<RefreshTokenRequest>,
) -> Result<Json<TokenPair>> {
    // Extract device info for token binding verification
    let device_info = DeviceInfo {
        user_agent: headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(String::from),
        accept_language: headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok())
            .map(String::from),
        ip_subnet: DeviceInfo::extract_subnet(&client_ip.0),
    };

    let token_pair = state
        .token_service
        .refresh_token(&request.refresh_token, Some(&api_key.client_project), Some(&device_info))
        .await?;

    Ok(Json(token_pair))
}

pub async fn validate_token(
    State(state): State<TokenHandlerState>,
    Json(request): Json<ValidateTokenRequest>,
) -> Json<ValidateTokenResponse> {
    let response = state.token_service.validate_access_token(&request.token);

    match response {
        Ok(resp) => Json(resp),
        Err(_) => Json(ValidateTokenResponse {
            valid: false,
            user_id: None,
            email: None,
            expires_at: None,
        }),
    }
}

pub async fn revoke_token(
    State(state): State<TokenHandlerState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(request): Json<RevokeTokenRequest>,
) -> Result<Json<serde_json::Value>> {
    if request.revoke_all {
        state.token_service.revoke_all_user_tokens(&user.user_id);
        tracing::info!(user_id = %user.user_id, "All tokens revoked for user");
        return Ok(Json(serde_json::json!({
            "success": true,
            "message": "All tokens have been revoked"
        })));
    }

    if let Some(refresh_token) = &request.refresh_token {
        state.token_service.revoke_refresh_token(refresh_token)?;
        return Ok(Json(serde_json::json!({
            "success": true,
            "message": "Token has been revoked"
        })));
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "No action taken"
    })))
}
