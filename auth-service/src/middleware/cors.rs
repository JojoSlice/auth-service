use axum::{
    extract::Request,
    http::{header, HeaderValue, Method},
    middleware::Next,
    response::Response,
};
use tower_http::cors::{Any, CorsLayer};

use crate::config::CorsConfig;
use crate::models::ValidatedApiKey;

pub fn create_cors_layer(config: &CorsConfig) -> CorsLayer {
    let origins: Vec<HeaderValue> = config
        .default_allowed_origins
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    if origins.is_empty() || config.default_allowed_origins.contains("*") {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                header::ACCEPT,
                header::HeaderName::from_static("x-api-key"),
                header::HeaderName::from_static("x-request-id"),
            ])
            .expose_headers([header::HeaderName::from_static("x-request-id")])
            .max_age(std::time::Duration::from_secs(3600))
    } else {
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                header::ACCEPT,
                header::HeaderName::from_static("x-api-key"),
                header::HeaderName::from_static("x-request-id"),
            ])
            .expose_headers([header::HeaderName::from_static("x-request-id")])
            .max_age(std::time::Duration::from_secs(3600))
    }
}

pub async fn dynamic_cors_middleware(request: Request, next: Next) -> Response {
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let _is_preflight = request.method() == Method::OPTIONS;

    let allowed_origins = request
        .extensions()
        .get::<ValidatedApiKey>()
        .map(|k| k.allowed_origins.clone());

    let mut response = next.run(request).await;

    if let (Some(origin), Some(allowed)) = (&origin, &allowed_origins) {
        let is_allowed = allowed.iter().any(|o| o == "*" || o == origin);

        if is_allowed {
            if let Ok(origin_value) = HeaderValue::from_str(origin) {
                response
                    .headers_mut()
                    .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_value);
                response.headers_mut().insert(
                    header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                    HeaderValue::from_static("true"),
                );
            }
        }
    }

    response
}
