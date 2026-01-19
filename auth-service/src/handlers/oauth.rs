use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::error::{AppError, Result};
use crate::models::{ProviderName, ValidatedApiKey};
use crate::oauth::{GitHubOAuthProvider, GoogleOAuthProvider, OAuthProvider};
use crate::services::AuthService;

#[derive(Clone)]
pub struct OAuthHandlerState {
    pub auth_service: Arc<AuthService>,
    pub google_provider: Arc<GoogleOAuthProvider>,
    pub github_provider: Arc<GitHubOAuthProvider>,
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
        .map_err(|_| AppError::BadRequest(format!("Unknown provider: {}", provider)))?;

    let oauth_state = state
        .auth_service
        .create_oauth_state(&api_key.client_project, request.redirect_uri);

    let scopes: Vec<&str> = request
        .scopes
        .as_ref()
        .map(|s| s.split(',').map(|s| s.trim()).collect())
        .unwrap_or_default();

    let authorization_url = match provider_name {
        ProviderName::Google => state.google_provider.authorization_url(&oauth_state, &scopes),
        ProviderName::Github => state.github_provider.authorization_url(&oauth_state, &scopes),
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

pub async fn oauth_callback(
    State(state): State<OAuthHandlerState>,
    Path(provider): Path<String>,
    Query(query): Query<OAuthCallbackQuery>,
) -> Response {
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
                    "error_description": format!("Unknown provider: {}", provider)
                })),
            )
                .into_response();
        }
    };

    let (client_project, redirect_uri) = match state
        .auth_service
        .validate_and_consume_state(&query.state)
    {
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
        .handle_oauth_callback(oauth_provider, &query.code, &client_project)
        .await
    {
        Ok(result) => result,
        Err(e) => {
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

    if let Some(redirect_uri) = redirect_uri {
        let redirect_url = format!(
            "{}?access_token={}&refresh_token={}&token_type={}&expires_in={}",
            redirect_uri,
            token_pair.access_token,
            token_pair.refresh_token,
            token_pair.token_type,
            token_pair.expires_in
        );
        return Redirect::temporary(&redirect_url).into_response();
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
