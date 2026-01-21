use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ApiKey {
    pub id: String,
    pub key_hash: String,
    pub key_prefix: String,
    pub name: String,
    pub client_project: String,
    pub allowed_origins: String,
    pub is_active: bool,
    pub rate_limit_per_minute: i32,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub last_used_at: Option<String>,
}

impl ApiKey {
    #[must_use]
    pub fn new(
        key_hash: String,
        key_prefix: String,
        name: String,
        client_project: String,
        allowed_origins: &[String],
    ) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            id: Uuid::new_v4().to_string(),
            key_hash,
            key_prefix,
            name,
            client_project,
            allowed_origins: allowed_origins.join(","),
            is_active: true,
            rate_limit_per_minute: 60,
            expires_at: None,
            created_at: now.clone(),
            updated_at: now,
            last_used_at: None,
        }
    }

    #[must_use]
    pub fn with_rate_limit(mut self, rate_limit: i32) -> Self {
        self.rate_limit_per_minute = rate_limit;
        self
    }

    #[must_use]
    pub fn with_expiration(mut self, expires_at: String) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    #[must_use]
    pub fn get_allowed_origins(&self) -> Vec<String> {
        self.allowed_origins
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    #[must_use]
    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        let origins = self.get_allowed_origins();
        if origins.iter().any(|o| o == "*") {
            return true;
        }
        origins.iter().any(|o| o == origin)
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = &self.expires_at {
            if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires_at) {
                return exp < Utc::now();
            }
        }
        false
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedApiKey {
    pub id: String,
    pub client_project: String,
    pub allowed_origins: Vec<String>,
    pub rate_limit_per_minute: i32,
}

impl From<ApiKey> for ValidatedApiKey {
    fn from(key: ApiKey) -> Self {
        let allowed_origins = key.get_allowed_origins();
        Self {
            id: key.id,
            client_project: key.client_project,
            allowed_origins,
            rate_limit_per_minute: key.rate_limit_per_minute,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ApiKeyResponse {
    pub id: String,
    pub key_prefix: String,
    pub name: String,
    pub client_project: String,
    pub is_active: bool,
    pub rate_limit_per_minute: i32,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

impl From<ApiKey> for ApiKeyResponse {
    fn from(key: ApiKey) -> Self {
        Self {
            id: key.id,
            key_prefix: key.key_prefix,
            name: key.name,
            client_project: key.client_project,
            is_active: key.is_active,
            rate_limit_per_minute: key.rate_limit_per_minute,
            expires_at: key.expires_at,
            created_at: key.created_at,
            last_used_at: key.last_used_at,
        }
    }
}
