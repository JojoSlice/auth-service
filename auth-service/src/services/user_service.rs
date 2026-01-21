use std::sync::Arc;

use crate::db::{OAuthProviderRepository, UserRepository};
use crate::error::{AppError, Result};
use crate::models::{UpdateUserRequest, User, UserProfile};

pub struct UserService {
    user_repository: Arc<UserRepository>,
    oauth_provider_repository: Arc<OAuthProviderRepository>,
}

impl UserService {
    #[must_use]
    pub fn new(
        user_repository: Arc<UserRepository>,
        oauth_provider_repository: Arc<OAuthProviderRepository>,
    ) -> Self {
        Self {
            user_repository,
            oauth_provider_repository,
        }
    }

    pub async fn get_profile(&self, user_id: &str) -> Result<UserProfile> {
        let user = self
            .user_repository
            .find_by_id(user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        if !user.is_active {
            return Err(AppError::Forbidden);
        }

        Ok(user.into())
    }

    pub async fn update_profile(
        &self,
        user_id: &str,
        update: &UpdateUserRequest,
    ) -> Result<UserProfile> {
        let user = self
            .user_repository
            .find_by_id(user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        if !user.is_active {
            return Err(AppError::Forbidden);
        }

        if let Some(ref display_name) = update.display_name {
            self.user_repository
                .update_display_name(user_id, Some(display_name))
                .await?;
        }

        let updated_user = self
            .user_repository
            .find_by_id(user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        tracing::info!(user_id = %user_id, "User profile updated");

        Ok(updated_user.into())
    }

    pub async fn delete_account(&self, user_id: &str) -> Result<()> {
        let user = self
            .user_repository
            .find_by_id(user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        if !user.is_active {
            return Err(AppError::NotFound("User not found".to_string()));
        }

        self.oauth_provider_repository
            .delete_by_user_id(user_id)
            .await?;

        self.user_repository.delete(user_id).await?;

        tracing::info!(user_id = %user_id, "User account deleted");

        Ok(())
    }

    pub async fn deactivate_account(&self, user_id: &str) -> Result<()> {
        let user = self
            .user_repository
            .find_by_id(user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        if !user.is_active {
            return Err(AppError::NotFound("User not found".to_string()));
        }

        self.user_repository.deactivate(user_id).await?;

        tracing::info!(user_id = %user_id, "User account deactivated");

        Ok(())
    }

    pub async fn get_user_by_id(&self, user_id: &str) -> Result<Option<User>> {
        self.user_repository.find_by_id(user_id).await
    }
}

impl Clone for UserService {
    fn clone(&self) -> Self {
        Self {
            user_repository: Arc::clone(&self.user_repository),
            oauth_provider_repository: Arc::clone(&self.oauth_provider_repository),
        }
    }
}
