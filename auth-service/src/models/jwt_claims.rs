use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,
    pub email: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_project: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub family_id: String,
    pub generation: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_project: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

impl TokenPair {
    pub fn new(access_token: String, refresh_token: String, expires_in: i64) -> Self {
        Self {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RefreshTokenFamily {
    pub family_id: String,
    pub user_id: String,
    pub current_generation: u32,
    pub created_at: String,
    pub last_used_at: String,
    pub is_revoked: bool,
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct ValidateTokenRequest {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct RevokeTokenRequest {
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub revoke_all: bool,
}

#[derive(Debug, Serialize)]
pub struct ValidateTokenResponse {
    pub valid: bool,
    pub user_id: Option<String>,
    pub email: Option<String>,
    pub expires_at: Option<i64>,
}
