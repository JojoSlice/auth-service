use axum::{
    extract::{ConnectInfo, Request, State},
    middleware::Next,
    response::Response,
};
use std::{net::SocketAddr, sync::Arc};

use crate::db::AuditLogRepository;
use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::ip_filter::extract_client_ip;
use crate::middleware::request_id::RequestId;
use crate::models::{AuditEventType, AuditLogBuilder};

#[derive(Clone)]
pub struct AuditState {
    pub repository: Arc<AuditLogRepository>,
}

pub async fn audit_middleware(
    State(state): State<AuditState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let client_ip = extract_client_ip(&request, &addr);

    let request_id = request
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone());

    let user_id = request
        .extensions()
        .get::<AuthenticatedUser>()
        .map(|u| u.user_id.clone());

    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let response = next.run(request).await;

    let status_code = response.status().as_u16() as i32;

    let event_type = determine_event_type(&path, &method, status_code);

    if let Some(event_type) = event_type {
        let mut builder = AuditLogBuilder::new(event_type)
            .ip_address(&client_ip)
            .endpoint(&path)
            .http_method(&method)
            .status_code(status_code);

        if let Some(ref req_id) = request_id {
            builder = builder.request_id(req_id);
        }

        if let Some(ref uid) = user_id {
            builder = builder.user_id(uid);
        }

        if let Some(ref ua) = user_agent {
            builder = builder.user_agent(ua);
        }

        let log = builder.build();

        if let Err(e) = state.repository.create(&log).await {
            tracing::error!(error = %e, "Failed to create audit log");
        }
    }

    response
}

fn determine_event_type(path: &str, method: &str, status_code: i32) -> Option<AuditEventType> {
    if path.contains("/auth/oauth") && path.contains("/init") {
        return Some(AuditEventType::OAuthInitiated);
    }

    if path.contains("/auth/oauth") && path.contains("/callback") {
        if status_code >= 200 && status_code < 300 {
            return Some(AuditEventType::OAuthSuccess);
        } else {
            return Some(AuditEventType::OAuthFailure);
        }
    }

    if path.contains("/token/refresh") && method == "POST" {
        return Some(AuditEventType::TokenRefreshed);
    }

    if path.contains("/token/validate") && method == "POST" {
        if status_code >= 200 && status_code < 300 {
            return Some(AuditEventType::TokenValidated);
        } else {
            return Some(AuditEventType::TokenValidationFailed);
        }
    }

    if path.contains("/token/revoke") && method == "POST" {
        return Some(AuditEventType::TokenRevoked);
    }

    if path.contains("/user/profile") && method == "PATCH" {
        return Some(AuditEventType::UserUpdated);
    }

    if path.contains("/user/account") && method == "DELETE" {
        return Some(AuditEventType::UserDeleted);
    }

    if path.contains("/admin") {
        return Some(AuditEventType::AdminAction);
    }

    if status_code == 401 {
        return Some(AuditEventType::UnauthorizedAccess);
    }

    if status_code == 429 {
        return Some(AuditEventType::RateLimitExceeded);
    }

    None
}
