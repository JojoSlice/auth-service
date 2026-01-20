use chrono::Utc;
use std::sync::Arc;

use crate::db::{OAuthProviderRepository, UserRepository};
use crate::error::{AppError, Result};
use crate::models::{CreateUserFromOAuth, DeviceInfo, OAuthProvider, TokenPair, User};
use crate::oauth::{OAuthProvider as OAuthProviderTrait, OAuthStateManager, OAuthUserInfo};
use crate::security::{EncryptionService, JwtService};

pub struct AuthService {
    user_repository: Arc<UserRepository>,
    oauth_provider_repository: Arc<OAuthProviderRepository>,
    jwt_service: Arc<JwtService>,
    encryption_service: Arc<EncryptionService>,
    state_manager: Arc<OAuthStateManager>,
}

impl AuthService {
    pub fn new(
        user_repository: Arc<UserRepository>,
        oauth_provider_repository: Arc<OAuthProviderRepository>,
        jwt_service: Arc<JwtService>,
        encryption_service: Arc<EncryptionService>,
        state_manager: Arc<OAuthStateManager>,
    ) -> Self {
        Self {
            user_repository,
            oauth_provider_repository,
            jwt_service,
            encryption_service,
            state_manager,
        }
    }

    pub fn create_oauth_state(&self, client_project: &str, redirect_uri: Option<String>) -> String {
        self.state_manager.create_state(client_project, redirect_uri)
    }

    pub fn validate_and_consume_state(&self, state: &str) -> Result<(String, Option<String>)> {
        let state_data = self.state_manager.validate_and_consume(state)?;
        Ok((state_data.client_project, state_data.redirect_uri))
    }

    pub async fn handle_oauth_callback(
        &self,
        provider: &dyn OAuthProviderTrait,
        code: &str,
        client_project: &str,
        device_info: Option<&DeviceInfo>,
    ) -> Result<(User, TokenPair)> {
        let tokens = provider.exchange_code(code).await?;

        let user_info = provider.get_user_info(&tokens.access_token).await?;

        let user = self.find_or_create_user(&user_info).await?;

        self.store_oauth_provider(&user.id, &user_info, &tokens)
            .await?;

        self.user_repository.update_last_login(&user.id).await?;

        // Compute device hash for token binding
        let device_hash = device_info.map(|d| d.compute_hash());

        let token_pair = self.jwt_service.create_token_pair(
            &user.id,
            &user.email,
            Some(client_project),
            None,
            0,
            device_hash.as_deref(),
        )?;

        tracing::info!(
            user_id = %user.id,
            provider = %user_info.provider,
            device_bound = device_hash.is_some(),
            "User authenticated via OAuth"
        );

        Ok((user, token_pair))
    }

    async fn find_or_create_user(&self, user_info: &OAuthUserInfo) -> Result<User> {
        if let Some(oauth_provider) = self
            .oauth_provider_repository
            .find_by_provider_user(user_info.provider, &user_info.provider_user_id)
            .await?
        {
            if let Some(user) = self.user_repository.find_by_id(&oauth_provider.user_id).await? {
                if !user.is_active {
                    return Err(AppError::Forbidden);
                }
                return Ok(user);
            }
        }

        let create_data = CreateUserFromOAuth {
            email: user_info.email.clone(),
            display_name: user_info.display_name.clone(),
            profile_picture_url: user_info.profile_picture_url.clone(),
            email_verified: user_info.email_verified,
        };

        let user = self
            .user_repository
            .find_or_create_from_oauth(&create_data)
            .await?;

        tracing::info!(
            user_id = %user.id,
            email = %user.email,
            "Created new user from OAuth"
        );

        Ok(user)
    }

    async fn store_oauth_provider(
        &self,
        user_id: &str,
        user_info: &OAuthUserInfo,
        tokens: &crate::oauth::OAuthTokens,
    ) -> Result<()> {
        let access_token_encrypted = self.encryption_service.encrypt(&tokens.access_token)?;

        let refresh_token_encrypted = if let Some(ref refresh_token) = tokens.refresh_token {
            Some(self.encryption_service.encrypt(refresh_token)?)
        } else {
            None
        };

        let expires_at = tokens.expires_in.map(|secs| {
            (Utc::now() + chrono::Duration::seconds(secs as i64)).to_rfc3339()
        });

        let oauth_provider = OAuthProvider::new(
            user_id.to_string(),
            user_info.provider,
            user_info.provider_user_id.clone(),
        )
        .with_tokens(
            access_token_encrypted,
            refresh_token_encrypted,
            expires_at,
        );

        let oauth_provider = if let Some(ref scope) = tokens.scope {
            oauth_provider.with_scope(scope.clone())
        } else {
            oauth_provider
        };

        self.oauth_provider_repository.upsert(&oauth_provider).await?;

        Ok(())
    }
}

impl Clone for AuthService {
    fn clone(&self) -> Self {
        Self {
            user_repository: Arc::clone(&self.user_repository),
            oauth_provider_repository: Arc::clone(&self.oauth_provider_repository),
            jwt_service: Arc::clone(&self.jwt_service),
            encryption_service: Arc::clone(&self.encryption_service),
            state_manager: Arc::clone(&self.state_manager),
        }
    }
}
