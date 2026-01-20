use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderName {
    Google,
    Github,
}

impl ProviderName {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProviderName::Google => "google",
            ProviderName::Github => "github",
        }
    }
}

impl std::fmt::Display for ProviderName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for ProviderName {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "google" => Ok(ProviderName::Google),
            "github" => Ok(ProviderName::Github),
            _ => Err(format!("Unknown provider: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OAuthProvider {
    pub id: String,
    pub user_id: String,
    pub provider_name: String,
    pub provider_user_id: String,
    pub access_token_encrypted: Option<String>,
    pub refresh_token_encrypted: Option<String>,
    pub token_expires_at: Option<String>,
    pub scope: Option<String>,
    pub provider_data: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl OAuthProvider {
    pub fn new(user_id: String, provider_name: ProviderName, provider_user_id: String) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            provider_name: provider_name.to_string(),
            provider_user_id,
            access_token_encrypted: None,
            refresh_token_encrypted: None,
            token_expires_at: None,
            scope: None,
            provider_data: None,
            created_at: now.clone(),
            updated_at: now,
        }
    }

    pub fn with_tokens(
        mut self,
        access_token_encrypted: String,
        refresh_token_encrypted: Option<String>,
        expires_at: Option<String>,
    ) -> Self {
        self.access_token_encrypted = Some(access_token_encrypted);
        self.refresh_token_encrypted = refresh_token_encrypted;
        self.token_expires_at = expires_at;
        self
    }

    pub fn with_scope(mut self, scope: String) -> Self {
        self.scope = Some(scope);
        self
    }

    pub fn with_provider_data(mut self, data: String) -> Self {
        self.provider_data = Some(data);
        self
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleUserInfo {
    pub id: String,
    pub email: String,
    pub verified_email: Option<bool>,
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitHubUserInfo {
    pub id: i64,
    pub login: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitHubEmail {
    pub email: String,
    pub primary: bool,
    pub verified: bool,
}
