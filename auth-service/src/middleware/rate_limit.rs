use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde_json::json;
use std::{net::SocketAddr, sync::Arc};

use crate::config::RateLimitConfig;
use crate::models::ValidatedApiKey;

#[derive(Clone)]
pub struct RateLimiter {
    ip_limits: Arc<DashMap<String, RateLimitBucket>>,
    api_key_limits: Arc<DashMap<String, RateLimitBucket>>,
    config: RateLimitConfig,
}

struct RateLimitBucket {
    count: u32,
    window_start: DateTime<Utc>,
}

impl RateLimiter {
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            ip_limits: Arc::new(DashMap::new()),
            api_key_limits: Arc::new(DashMap::new()),
            config,
        }
    }

    #[must_use]
    pub fn check_ip(&self, ip: &str) -> bool {
        if !self.config.enabled {
            return true;
        }

        self.check_limit(&self.ip_limits, ip, self.config.global_per_minute)
    }

    #[must_use]
    pub fn check_api_key(&self, key_id: &str, custom_limit: Option<i32>) -> bool {
        if !self.config.enabled {
            return true;
        }

        let limit = custom_limit.map_or(self.config.global_per_minute, |l| l as u32);
        self.check_limit(&self.api_key_limits, key_id, limit)
    }

    fn check_limit(&self, map: &DashMap<String, RateLimitBucket>, key: &str, limit: u32) -> bool {
        let now = Utc::now();
        let window_duration = Duration::minutes(1);

        let mut entry = map
            .entry(key.to_string())
            .or_insert_with(|| RateLimitBucket {
                count: 0,
                window_start: now,
            });

        if now - entry.window_start > window_duration {
            entry.count = 1;
            entry.window_start = now;
            return true;
        }

        if entry.count >= limit {
            return false;
        }

        entry.count += 1;
        true
    }

    pub fn cleanup(&self) {
        let now = Utc::now();
        let window_duration = Duration::minutes(1);

        self.ip_limits
            .retain(|_, v| now - v.window_start <= window_duration);
        self.api_key_limits
            .retain(|_, v| now - v.window_start <= window_duration);
    }
}

pub async fn rate_limit_middleware(
    State(limiter): State<RateLimiter>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let ip = addr.ip().to_string();

    if !limiter.check_ip(&ip) {
        tracing::warn!(ip = %ip, "Rate limit exceeded for IP");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "Too Many Requests",
                "error_description": "Rate limit exceeded. Please try again later."
            })),
        )
            .into_response();
    }

    if let Some(api_key) = request.extensions().get::<ValidatedApiKey>() {
        if !limiter.check_api_key(&api_key.id, Some(api_key.rate_limit_per_minute)) {
            tracing::warn!(
                api_key_id = %api_key.id,
                client_project = %api_key.client_project,
                "Rate limit exceeded for API key"
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": "Too Many Requests",
                    "error_description": "Rate limit exceeded for this API key. Please try again later."
                })),
            )
                .into_response();
        }
    }

    next.run(request).await
}
