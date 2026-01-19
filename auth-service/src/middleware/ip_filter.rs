use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::{net::SocketAddr, sync::Arc};

use crate::db::IpFilterRepository;

#[derive(Clone)]
pub struct IpFilterState {
    pub repository: Arc<IpFilterRepository>,
}

pub async fn ip_filter_middleware(
    State(state): State<IpFilterState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let ip = addr.ip().to_string();

    match state.repository.is_blacklisted(&ip).await {
        Ok(true) => {
            tracing::warn!(ip = %ip, "Blocked request from blacklisted IP");
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "Forbidden",
                    "error_description": "Your IP address has been blocked"
                })),
            )
                .into_response();
        }
        Ok(false) => {}
        Err(e) => {
            tracing::error!(error = %e, "Error checking IP blacklist");
        }
    }

    next.run(request).await
}

pub fn extract_client_ip(request: &Request, addr: &SocketAddr) -> String {
    request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            request
                .headers()
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(String::from)
        })
        .unwrap_or_else(|| addr.ip().to_string())
}

#[derive(Clone, Debug)]
pub struct ClientIp(pub String);

impl ClientIp {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
