use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::Arc;

use crate::models::AccessTokenClaims;
use crate::security::JwtService;

#[derive(Clone)]
pub struct AuthState {
    pub jwt_service: Arc<JwtService>,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub email: String,
    pub client_project: Option<String>,
}

impl From<AccessTokenClaims> for AuthenticatedUser {
    fn from(claims: AccessTokenClaims) -> Self {
        Self {
            user_id: claims.sub,
            email: claims.email,
            client_project: claims.client_project,
        }
    }
}

pub async fn auth_middleware(
    State(state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Response {
    let auth_header = match request.headers().get(header::AUTHORIZATION) {
        Some(value) => match value.to_str() {
            Ok(s) => s,
            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "Unauthorized",
                        "error_description": "Invalid authorization header"
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
                    "error_description": "Missing authorization header"
                })),
            )
                .into_response();
        }
    };

    let token = if auth_header.starts_with("Bearer ") {
        &auth_header[7..]
    } else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Unauthorized",
                "error_description": "Invalid authorization scheme. Use 'Bearer <token>'"
            })),
        )
            .into_response();
    };

    match state.jwt_service.verify_access_token(token) {
        Ok(claims) => {
            let user: AuthenticatedUser = claims.into();
            request.extensions_mut().insert(user);
            next.run(request).await
        }
        Err(e) => {
            tracing::debug!(error = %e, "Token verification failed");
            let (status, message) = match e {
                crate::error::AppError::TokenExpired => {
                    (StatusCode::UNAUTHORIZED, "Token has expired")
                }
                _ => (StatusCode::UNAUTHORIZED, "Invalid token"),
            };

            (
                status,
                Json(json!({
                    "error": "Unauthorized",
                    "error_description": message
                })),
            )
                .into_response()
        }
    }
}

pub async fn optional_auth_middleware(
    State(state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Response {
    if let Some(auth_header) = request.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                if let Ok(claims) = state.jwt_service.verify_access_token(token) {
                    let user: AuthenticatedUser = claims.into();
                    request.extensions_mut().insert(user);
                }
            }
        }
    }

    next.run(request).await
}
