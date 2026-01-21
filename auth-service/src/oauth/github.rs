use async_trait::async_trait;
use oauth2::{
    basic::{BasicClient, BasicErrorResponseType, BasicTokenType},
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    EndpointNotSet, EndpointSet, RedirectUrl, RevocationErrorResponseType, Scope,
    StandardErrorResponse, StandardRevocableToken, StandardTokenIntrospectionResponse,
    StandardTokenResponse, TokenResponse, TokenUrl,
};
use reqwest::Client;
use secrecy::ExposeSecret;

use super::provider::{OAuthProvider, OAuthTokens, OAuthUserInfo};
use crate::config::GitHubOAuthConfig;
use crate::error::{AppError, Result};
use crate::models::{GitHubEmail, GitHubUserInfo, ProviderName};

const GITHUB_AUTH_URL: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const GITHUB_USER_URL: &str = "https://api.github.com/user";
const GITHUB_EMAILS_URL: &str = "https://api.github.com/user/emails";

/// `OAuth2` client with auth and token endpoints configured
type ConfiguredClient = oauth2::Client<
    StandardErrorResponse<BasicErrorResponseType>,
    StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>,
    StandardRevocableToken,
    StandardErrorResponse<RevocationErrorResponseType>,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;

pub struct GitHubOAuthProvider {
    client: ConfiguredClient,
    http_client: Client,
}

impl GitHubOAuthProvider {
    pub fn new(config: &GitHubOAuthConfig) -> Result<Self> {
        let auth_url = AuthUrl::new(GITHUB_AUTH_URL.to_string())
            .map_err(|e| AppError::OAuth(format!("Invalid auth URL: {e}")))?;
        let token_url = TokenUrl::new(GITHUB_TOKEN_URL.to_string())
            .map_err(|e| AppError::OAuth(format!("Invalid token URL: {e}")))?;
        let redirect_url = RedirectUrl::new(config.redirect_uri.clone())
            .map_err(|e| AppError::OAuth(format!("Invalid redirect URI: {e}")))?;

        let client = BasicClient::new(ClientId::new(config.client_id.expose_secret().to_string()))
            .set_client_secret(ClientSecret::new(
                config.client_secret.expose_secret().to_string(),
            ))
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_redirect_uri(redirect_url);

        let http_client = Client::builder()
            .user_agent("Auth-Service")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| AppError::OAuth(format!("Failed to create HTTP client: {e}")))?;

        Ok(Self {
            client,
            http_client,
        })
    }

    async fn get_primary_email(&self, access_token: &str) -> Result<(String, bool)> {
        let response = self
            .http_client
            .get(GITHUB_EMAILS_URL)
            .bearer_auth(access_token)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| AppError::OAuth(format!("Failed to get user emails: {e}")))?;

        if !response.status().is_success() {
            return Err(AppError::OAuth("Failed to fetch GitHub emails".to_string()));
        }

        let emails: Vec<GitHubEmail> = response
            .json()
            .await
            .map_err(|e| AppError::OAuth(format!("Failed to parse emails: {e}")))?;

        let primary_email = emails
            .iter()
            .find(|e| e.primary && e.verified)
            .or_else(|| emails.iter().find(|e| e.primary))
            .or_else(|| emails.iter().find(|e| e.verified))
            .or_else(|| emails.first())
            .ok_or_else(|| AppError::OAuth("No email found for GitHub user".to_string()))?;

        Ok((primary_email.email.clone(), primary_email.verified))
    }
}

#[async_trait]
impl OAuthProvider for GitHubOAuthProvider {
    fn name(&self) -> ProviderName {
        ProviderName::Github
    }

    fn authorization_url(&self, state: &str, scopes: &[&str]) -> String {
        let scopes_to_use: Vec<Scope> = if scopes.is_empty() {
            self.default_scopes()
                .iter()
                .map(|s| Scope::new(s.to_string()))
                .collect()
        } else {
            scopes.iter().map(|s| Scope::new(s.to_string())).collect()
        };

        let mut auth_request = self
            .client
            .authorize_url(|| CsrfToken::new(state.to_string()));

        for scope in scopes_to_use {
            auth_request = auth_request.add_scope(scope);
        }

        let (url, _) = auth_request.url();
        url.to_string()
    }

    async fn exchange_code(&self, code: &str) -> Result<OAuthTokens> {
        let http_client = self.http_client.clone();
        let token_result = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(&http_client)
            .await
            .map_err(|e| AppError::OAuth(format!("Failed to exchange code: {e:?}")))?;

        Ok(OAuthTokens {
            access_token: token_result.access_token().secret().clone(),
            refresh_token: token_result.refresh_token().map(|t| t.secret().clone()),
            expires_in: token_result.expires_in().map(|d| d.as_secs()),
            scope: token_result.scopes().map(|s| {
                s.iter()
                    .map(|sc| sc.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            }),
        })
    }

    async fn get_user_info(&self, access_token: &str) -> Result<OAuthUserInfo> {
        let response = self
            .http_client
            .get(GITHUB_USER_URL)
            .bearer_auth(access_token)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| AppError::OAuth(format!("Failed to get user info: {e}")))?;

        if !response.status().is_success() {
            let error_body = response.text().await.unwrap_or_default();
            return Err(AppError::OAuth(format!("GitHub API error: {error_body}")));
        }

        let user_info: GitHubUserInfo = response
            .json()
            .await
            .map_err(|e| AppError::OAuth(format!("Failed to parse user info: {e}")))?;

        let (email, email_verified) = if let Some(email) = user_info.email {
            (email, true)
        } else {
            self.get_primary_email(access_token).await?
        };

        Ok(OAuthUserInfo {
            provider: ProviderName::Github,
            provider_user_id: user_info.id.to_string(),
            email,
            email_verified,
            display_name: user_info.name.or(Some(user_info.login)),
            profile_picture_url: user_info.avatar_url,
        })
    }

    fn default_scopes(&self) -> Vec<&'static str> {
        vec!["read:user", "user:email"]
    }
}
