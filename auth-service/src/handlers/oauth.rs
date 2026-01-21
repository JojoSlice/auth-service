use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::db::AuditLogRepository;
use crate::error::{AppError, Result};
use crate::middleware::ClientIp;
use crate::models::{AuditEventType, AuditLogBuilder, DeviceInfo, ProviderName, ValidatedApiKey};
use crate::oauth::{GitHubOAuthProvider, GoogleOAuthProvider, OAuthProvider};
use crate::services::{AnomalyDetectionService, AnomalyResult, AuthService};

#[derive(Clone)]
pub struct OAuthHandlerState {
    pub auth_service: Arc<AuthService>,
    pub google_provider: Arc<GoogleOAuthProvider>,
    pub github_provider: Arc<GitHubOAuthProvider>,
    pub anomaly_detection_service: Arc<AnomalyDetectionService>,
    pub audit_log_repository: Arc<AuditLogRepository>,
}

#[derive(Debug, Deserialize)]
pub struct OAuthInitRequest {
    #[serde(default)]
    pub scopes: Option<String>,
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OAuthInitResponse {
    pub authorization_url: String,
    pub state: String,
}

#[derive(Debug, Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: String,
    pub state: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OAuthCallbackResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user: OAuthUserResponse,
}

#[derive(Debug, Serialize)]
pub struct OAuthUserResponse {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub profile_picture_url: Option<String>,
}

pub async fn oauth_init(
    State(state): State<OAuthHandlerState>,
    Path(provider): Path<String>,
    Extension(api_key): Extension<ValidatedApiKey>,
    Query(request): Query<OAuthInitRequest>,
) -> Result<Json<OAuthInitResponse>> {
    let provider_name: ProviderName = provider
        .parse()
        .map_err(|_| AppError::BadRequest(format!("Unknown provider: {provider}")))?;

    let oauth_state = state
        .auth_service
        .create_oauth_state(&api_key.client_project, request.redirect_uri);

    let scopes: Vec<&str> = request
        .scopes
        .as_ref()
        .map(|s| s.split(',').map(str::trim).collect())
        .unwrap_or_default();

    let authorization_url = match provider_name {
        ProviderName::Google => state
            .google_provider
            .authorization_url(&oauth_state, &scopes),
        ProviderName::Github => state
            .github_provider
            .authorization_url(&oauth_state, &scopes),
    };

    tracing::info!(
        provider = %provider_name,
        client_project = %api_key.client_project,
        "OAuth flow initiated"
    );

    Ok(Json(OAuthInitResponse {
        authorization_url,
        state: oauth_state,
    }))
}

#[allow(clippy::too_many_lines)]
pub async fn oauth_callback(
    State(state): State<OAuthHandlerState>,
    Path(provider): Path<String>,
    Query(query): Query<OAuthCallbackQuery>,
    headers: HeaderMap,
    Extension(client_ip): Extension<ClientIp>,
) -> Response {
    let ip = &client_ip.0;
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());

    // Check if IP is locked out due to previous suspicious activity
    if let Some(AnomalyResult::BruteForceDetected { lockout_until, .. }) =
        state.anomaly_detection_service.check_ip_lockout(ip)
    {
        tracing::warn!(
            ip = %ip,
            lockout_until = %lockout_until,
            "OAuth callback blocked - IP is locked out"
        );
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "too_many_requests",
                "error_description": "Too many failed attempts. Please try again later."
            })),
        )
            .into_response();
    }

    // Extract device info for token binding
    let device_info = DeviceInfo {
        user_agent: user_agent.map(String::from),
        accept_language: headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok())
            .map(String::from),
        ip_subnet: DeviceInfo::extract_subnet(ip),
    };

    if let Some(error) = query.error {
        let description = query.error_description.unwrap_or_default();
        tracing::warn!(
            provider = %provider,
            error = %error,
            description = %description,
            "OAuth callback received error"
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": error,
                "error_description": description
            })),
        )
            .into_response();
    }

    let provider_name: ProviderName = match provider.parse() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_provider",
                    "error_description": format!("Unknown provider: {provider}")
                })),
            )
                .into_response();
        }
    };

    let (client_project, redirect_uri) =
        match state.auth_service.validate_and_consume_state(&query.state) {
            Ok((project, uri)) => (project, uri),
            Err(e) => {
                tracing::warn!(error = %e, "Invalid OAuth state");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_state",
                        "error_description": "Invalid or expired state parameter"
                    })),
                )
                    .into_response();
            }
        };

    let oauth_provider: &dyn OAuthProvider = match provider_name {
        ProviderName::Google => state.google_provider.as_ref(),
        ProviderName::Github => state.github_provider.as_ref(),
    };

    let (user, token_pair) = match state
        .auth_service
        .handle_oauth_callback(
            oauth_provider,
            &query.code,
            &client_project,
            Some(&device_info),
        )
        .await
    {
        Ok(result) => result,
        Err(e) => {
            // Record failed attempt for this IP
            let _ = state.anomaly_detection_service.record_failed_attempt(ip);

            tracing::error!(error = %e, provider = %provider_name, "OAuth callback failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "oauth_error",
                    "error_description": "Failed to complete OAuth flow"
                })),
            )
                .into_response();
        }
    };

    // Check for login anomalies
    let anomaly = state
        .anomaly_detection_service
        .check_login_anomaly(&user.id, ip, user_agent);

    // Record successful login
    state
        .anomaly_detection_service
        .record_successful_login(&user.id, ip, user_agent);

    // Log anomalies to audit log
    if anomaly.should_warn() {
        let anomaly_description = match &anomaly {
            AnomalyResult::UnusualLocation {
                previous_ip,
                current_ip,
            } => {
                format!(
                    "Login from new IP: {current_ip} (previous: {previous_ip})"
                )
            }
            AnomalyResult::ImpossibleTravel {
                previous_location,
                current_location,
                time_diff_minutes,
            } => {
                format!(
                    "Suspicious location change: {previous_location} -> {current_location} in {time_diff_minutes} minutes"
                )
            }
            AnomalyResult::UnusualPattern { reason } => {
                format!("Unusual pattern: {reason}")
            }
            _ => "Unknown anomaly".to_string(),
        };

        let audit_log = AuditLogBuilder::new(AuditEventType::LoginAnomaly)
            .user_id(&user.id)
            .ip_address(ip)
            .details(&anomaly_description)
            .build();

        if let Err(e) = state.audit_log_repository.create(&audit_log).await {
            tracing::error!(error = %e, "Failed to log anomaly to audit log");
        }

        tracing::warn!(
            user_id = %user.id,
            ip = %ip,
            anomaly = %anomaly_description,
            "Login anomaly detected"
        );
    }

    if let Some(redirect_uri) = redirect_uri {
        let final_redirect_url = format!(
            "{}?access_token={}&refresh_token={}&token_type={}&expires_in={}",
            redirect_uri,
            token_pair.access_token,
            token_pair.refresh_token,
            token_pair.token_type,
            token_pair.expires_in
        );
        return Redirect::temporary(&final_redirect_url).into_response();
    }

    Json(OAuthCallbackResponse {
        access_token: token_pair.access_token,
        refresh_token: token_pair.refresh_token,
        token_type: token_pair.token_type,
        expires_in: token_pair.expires_in,
        user: OAuthUserResponse {
            id: user.id,
            email: user.email,
            display_name: user.display_name,
            profile_picture_url: user.profile_picture_url,
        },
    })
    .into_response()
}
