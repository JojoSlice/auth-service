use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditEventType {
    OAuthInitiated,
    OAuthCallback,
    OAuthSuccess,
    OAuthFailure,
    TokenIssued,
    TokenRefreshed,
    TokenRevoked,
    TokenValidated,
    TokenValidationFailed,
    UserCreated,
    UserUpdated,
    UserDeleted,
    UserLogin,
    UserLogout,
    ApiKeyValidated,
    ApiKeyInvalid,
    ApiKeyExpired,
    RateLimitExceeded,
    IpBlocked,
    IpWhitelisted,
    UnauthorizedAccess,
    AdminAction,
    LoginAnomaly,
    BruteForceDetected,
}

impl AuditEventType {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditEventType::OAuthInitiated => "OAUTH_INITIATED",
            AuditEventType::OAuthCallback => "OAUTH_CALLBACK",
            AuditEventType::OAuthSuccess => "OAUTH_SUCCESS",
            AuditEventType::OAuthFailure => "OAUTH_FAILURE",
            AuditEventType::TokenIssued => "TOKEN_ISSUED",
            AuditEventType::TokenRefreshed => "TOKEN_REFRESHED",
            AuditEventType::TokenRevoked => "TOKEN_REVOKED",
            AuditEventType::TokenValidated => "TOKEN_VALIDATED",
            AuditEventType::TokenValidationFailed => "TOKEN_VALIDATION_FAILED",
            AuditEventType::UserCreated => "USER_CREATED",
            AuditEventType::UserUpdated => "USER_UPDATED",
            AuditEventType::UserDeleted => "USER_DELETED",
            AuditEventType::UserLogin => "USER_LOGIN",
            AuditEventType::UserLogout => "USER_LOGOUT",
            AuditEventType::ApiKeyValidated => "API_KEY_VALIDATED",
            AuditEventType::ApiKeyInvalid => "API_KEY_INVALID",
            AuditEventType::ApiKeyExpired => "API_KEY_EXPIRED",
            AuditEventType::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            AuditEventType::IpBlocked => "IP_BLOCKED",
            AuditEventType::IpWhitelisted => "IP_WHITELISTED",
            AuditEventType::UnauthorizedAccess => "UNAUTHORIZED_ACCESS",
            AuditEventType::AdminAction => "ADMIN_ACTION",
            AuditEventType::LoginAnomaly => "LOGIN_ANOMALY",
            AuditEventType::BruteForceDetected => "BRUTE_FORCE_DETECTED",
        }
    }
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditLog {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub user_id: Option<String>,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub endpoint: Option<String>,
    pub http_method: Option<String>,
    pub status_code: Option<i32>,
    pub error_message: Option<String>,
    pub metadata: Option<String>,
}

impl AuditLog {
    #[must_use]
    pub fn new(event_type: AuditEventType, ip_address: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            event_type: event_type.to_string(),
            user_id: None,
            ip_address,
            user_agent: None,
            request_id: None,
            endpoint: None,
            http_method: None,
            status_code: None,
            error_message: None,
            metadata: None,
        }
    }

    #[must_use]
    pub fn with_user(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }

    #[must_use]
    pub fn with_request_info(
        mut self,
        request_id: Option<String>,
        endpoint: String,
        http_method: String,
    ) -> Self {
        self.request_id = request_id;
        self.endpoint = Some(endpoint);
        self.http_method = Some(http_method);
        self
    }

    #[must_use]
    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    #[must_use]
    pub fn with_status_code(mut self, status_code: i32) -> Self {
        self.status_code = Some(status_code);
        self
    }

    #[must_use]
    pub fn with_error(mut self, error_message: String) -> Self {
        self.error_message = Some(error_message);
        self
    }

    #[must_use]
    pub fn with_metadata(mut self, metadata: &serde_json::Value) -> Self {
        self.metadata = Some(metadata.to_string());
        self
    }
}

#[derive(Debug)]
pub struct AuditLogBuilder {
    log: AuditLog,
}

impl AuditLogBuilder {
    #[must_use]
    pub fn new(event_type: AuditEventType) -> Self {
        Self {
            log: AuditLog::new(event_type, String::new()),
        }
    }

    #[must_use]
    pub fn user_id(mut self, user_id: &str) -> Self {
        self.log.user_id = Some(user_id.to_string());
        self
    }

    #[must_use]
    pub fn ip_address(mut self, ip: &str) -> Self {
        self.log.ip_address = ip.to_string();
        self
    }

    #[must_use]
    pub fn details(mut self, details: &str) -> Self {
        self.log.metadata = Some(serde_json::json!({ "details": details }).to_string());
        self
    }

    #[must_use]
    pub fn request_id(mut self, request_id: &str) -> Self {
        self.log.request_id = Some(request_id.to_string());
        self
    }

    #[must_use]
    pub fn endpoint(mut self, endpoint: &str) -> Self {
        self.log.endpoint = Some(endpoint.to_string());
        self
    }

    #[must_use]
    pub fn http_method(mut self, method: &str) -> Self {
        self.log.http_method = Some(method.to_string());
        self
    }

    #[must_use]
    pub fn user_agent(mut self, user_agent: &str) -> Self {
        self.log.user_agent = Some(user_agent.to_string());
        self
    }

    #[must_use]
    pub fn status_code(mut self, code: i32) -> Self {
        self.log.status_code = Some(code);
        self
    }

    #[must_use]
    pub fn error(mut self, error: &str) -> Self {
        self.log.error_message = Some(error.to_string());
        self
    }

    #[must_use]
    pub fn metadata(mut self, metadata: &serde_json::Value) -> Self {
        self.log.metadata = Some(metadata.to_string());
        self
    }

    #[must_use]
    pub fn build(self) -> AuditLog {
        self.log
    }
}
