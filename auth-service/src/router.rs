use axum::{
    middleware,
    routing::{delete, get, patch, post},
    Router,
};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

use crate::app_state::AppState;
use crate::handlers;
use crate::middleware::{
    api_key_middleware, audit_middleware, auth_middleware, create_cors_layer, ip_filter_middleware,
    rate_limit_middleware, request_id_middleware, security_headers_middleware,
};

pub fn create_router(state: AppState) -> Router {
    let cors = create_cors_layer(&state.config.cors);

    let health_routes = Router::new()
        .route("/health", get(handlers::health_check))
        .with_state(state.pool.clone());

    let oauth_init_routes = Router::new()
        .route(
            "/api/v1/auth/oauth/{provider}/init",
            post(handlers::oauth_init),
        )
        .layer(middleware::from_fn_with_state(
            state.api_key_state(),
            api_key_middleware,
        ))
        .with_state(state.oauth_handler_state());

    let oauth_callback_routes = Router::new()
        .route(
            "/api/v1/auth/oauth/{provider}/callback",
            get(handlers::oauth_callback),
        )
        .with_state(state.oauth_handler_state());

    let token_public_routes = Router::new()
        .route("/api/v1/auth/token/refresh", post(handlers::refresh_token))
        .route(
            "/api/v1/auth/token/validate",
            post(handlers::validate_token),
        )
        .layer(middleware::from_fn_with_state(
            state.api_key_state(),
            api_key_middleware,
        ))
        .with_state(state.token_handler_state());

    let token_auth_routes = Router::new()
        .route("/api/v1/auth/token/revoke", post(handlers::revoke_token))
        .layer(middleware::from_fn_with_state(
            state.auth_state(),
            auth_middleware,
        ))
        .with_state(state.token_handler_state());

    let user_routes = Router::new()
        .route("/api/v1/user/profile", get(handlers::get_profile))
        .route("/api/v1/user/profile", patch(handlers::update_profile))
        .route("/api/v1/user/account", delete(handlers::delete_account))
        .layer(middleware::from_fn_with_state(
            state.auth_state(),
            auth_middleware,
        ))
        .with_state(state.user_handler_state());

    let admin_routes = Router::new()
        .route("/api/v1/admin/api-keys", post(handlers::create_api_key))
        .route("/api/v1/admin/api-keys", get(handlers::list_api_keys))
        .route(
            "/api/v1/admin/api-keys/{key_id}",
            delete(handlers::revoke_api_key),
        )
        .route("/api/v1/admin/audit-logs", get(handlers::get_audit_logs))
        .route("/api/v1/admin/ip-filters", post(handlers::create_ip_filter))
        .route(
            "/api/v1/admin/ip-filters/{filter_type}",
            get(handlers::list_ip_filters),
        )
        .route(
            "/api/v1/admin/ip-filters/{filter_id}",
            delete(handlers::delete_ip_filter),
        )
        .layer(middleware::from_fn_with_state(
            state.admin_handler_state(),
            handlers::admin_ip_check,
        ))
        .layer(middleware::from_fn_with_state(
            state.api_key_state(),
            api_key_middleware,
        ))
        .with_state(state.admin_handler_state());

    Router::new()
        .merge(health_routes)
        .merge(oauth_init_routes)
        .merge(oauth_callback_routes)
        .merge(token_public_routes)
        .merge(token_auth_routes)
        .merge(user_routes)
        .merge(admin_routes)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(middleware::from_fn(security_headers_middleware))
                .layer(cors)
                .layer(middleware::from_fn(request_id_middleware))
                .layer(middleware::from_fn_with_state(
                    state.rate_limiter.clone(),
                    rate_limit_middleware,
                ))
                .layer(middleware::from_fn_with_state(
                    state.ip_filter_state(),
                    ip_filter_middleware,
                ))
                .layer(middleware::from_fn_with_state(
                    state.audit_state(),
                    audit_middleware,
                )),
        )
}
