use async_trait::async_trait;

use crate::error::Result;
use crate::models::ProviderName;

#[derive(Debug, Clone)]
pub struct OAuthUserInfo {
    pub provider: ProviderName,
    pub provider_user_id: String,
    pub email: String,
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub profile_picture_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
    pub scope: Option<String>,
}

#[async_trait]
pub trait OAuthProvider: Send + Sync {
    fn name(&self) -> ProviderName;

    fn authorization_url(&self, state: &str, scopes: &[&str]) -> String;

    async fn exchange_code(&self, code: &str) -> Result<OAuthTokens>;

    async fn get_user_info(&self, access_token: &str) -> Result<OAuthUserInfo>;

    fn default_scopes(&self) -> Vec<&'static str>;
}
