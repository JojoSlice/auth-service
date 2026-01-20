use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    Database(sqlx::Error),
    Configuration(config::ConfigError),
    OAuth(String),
    JwtError(jsonwebtoken::errors::Error),
    InvalidToken,
    TokenExpired,
    Unauthorized,
    Forbidden,
    NotFound(String),
    BadRequest(String),
    RateLimitExceeded,
    InternalServerError(String),
    ValidationError(String),
    DeviceMismatch,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    error_description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Database(e) => write!(f, "Database error: {}", e),
            AppError::Configuration(e) => write!(f, "Configuration error: {}", e),
            AppError::OAuth(msg) => write!(f, "OAuth error: {}", msg),
            AppError::JwtError(e) => write!(f, "JWT error: {}", e),
            AppError::InvalidToken => write!(f, "Invalid token"),
            AppError::TokenExpired => write!(f, "Token expired"),
            AppError::Unauthorized => write!(f, "Unauthorized"),
            AppError::Forbidden => write!(f, "Forbidden"),
            AppError::NotFound(msg) => write!(f, "Not found: {}", msg),
            AppError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            AppError::RateLimitExceeded => write!(f, "Rate limit exceeded"),
            AppError::InternalServerError(msg) => write!(f, "Internal server error: {}", msg),
            AppError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            AppError::DeviceMismatch => write!(f, "Device mismatch detected"),
        }
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_code, error_description) = match &self {
            AppError::Database(e) => {
                tracing::error!("Database error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Some("DATABASE_ERROR"),
                    "An internal database error occurred",
                )
            }
            AppError::Configuration(e) => {
                tracing::error!("Configuration error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Some("CONFIGURATION_ERROR"),
                    "Server configuration error",
                )
            }
            AppError::OAuth(msg) => (StatusCode::BAD_REQUEST, Some("OAUTH_ERROR"), msg.as_str()),
            AppError::JwtError(e) => {
                tracing::error!("JWT error: {:?}", e);
                (
                    StatusCode::UNAUTHORIZED,
                    Some("JWT_ERROR"),
                    "Invalid or malformed token",
                )
            }
            AppError::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                Some("INVALID_TOKEN"),
                "The provided token is invalid",
            ),
            AppError::TokenExpired => (
                StatusCode::UNAUTHORIZED,
                Some("TOKEN_EXPIRED"),
                "The token has expired",
            ),
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                Some("UNAUTHORIZED"),
                "Authentication required",
            ),
            AppError::Forbidden => (StatusCode::FORBIDDEN, Some("FORBIDDEN"), "Access forbidden"),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, Some("NOT_FOUND"), msg.as_str()),
            AppError::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, Some("BAD_REQUEST"), msg.as_str())
            }
            AppError::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                Some("RATE_LIMIT_EXCEEDED"),
                "Rate limit exceeded. Please try again later",
            ),
            AppError::InternalServerError(msg) => {
                tracing::error!("Internal server error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Some("INTERNAL_ERROR"),
                    "An internal server error occurred",
                )
            }
            AppError::ValidationError(msg) => (
                StatusCode::BAD_REQUEST,
                Some("VALIDATION_ERROR"),
                msg.as_str(),
            ),
            AppError::DeviceMismatch => (
                StatusCode::UNAUTHORIZED,
                Some("DEVICE_MISMATCH"),
                "Session is bound to a different device. Please log in again.",
            ),
        };

        let body = Json(ErrorResponse {
            error: status
                .canonical_reason()
                .unwrap_or("Unknown Error")
                .to_string(),
            error_description: error_description.to_string(),
            error_code: error_code.map(String::from),
            request_id: None,
        });

        (status, body).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        AppError::Database(err)
    }
}

impl From<config::ConfigError> for AppError {
    fn from(err: config::ConfigError) -> Self {
        AppError::Configuration(err)
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        AppError::JwtError(err)
    }
}

impl From<sqlx::migrate::MigrateError> for AppError {
    fn from(err: sqlx::migrate::MigrateError) -> Self {
        AppError::Database(sqlx::Error::Migrate(Box::new(err)))
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
