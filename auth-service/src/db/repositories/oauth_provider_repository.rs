use chrono::Utc;
use sqlx::SqlitePool;

use crate::error::Result;
use crate::models::{OAuthProvider, ProviderName};

pub struct OAuthProviderRepository {
    pool: SqlitePool,
}

impl OAuthProviderRepository {
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, provider: &OAuthProvider) -> Result<()> {
        sqlx::query(
            r"
            INSERT INTO oauth_providers (id, user_id, provider_name, provider_user_id, access_token_encrypted, refresh_token_encrypted, token_expires_at, scope, provider_data, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ",
        )
        .bind(&provider.id)
        .bind(&provider.user_id)
        .bind(&provider.provider_name)
        .bind(&provider.provider_user_id)
        .bind(&provider.access_token_encrypted)
        .bind(&provider.refresh_token_encrypted)
        .bind(&provider.token_expires_at)
        .bind(&provider.scope)
        .bind(&provider.provider_data)
        .bind(&provider.created_at)
        .bind(&provider.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<OAuthProvider>> {
        let provider =
            sqlx::query_as::<_, OAuthProvider>("SELECT * FROM oauth_providers WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;

        Ok(provider)
    }

    pub async fn find_by_user_id(&self, user_id: &str) -> Result<Vec<OAuthProvider>> {
        let providers =
            sqlx::query_as::<_, OAuthProvider>("SELECT * FROM oauth_providers WHERE user_id = ?")
                .bind(user_id)
                .fetch_all(&self.pool)
                .await?;

        Ok(providers)
    }

    pub async fn find_by_provider_user(
        &self,
        provider_name: ProviderName,
        provider_user_id: &str,
    ) -> Result<Option<OAuthProvider>> {
        let provider = sqlx::query_as::<_, OAuthProvider>(
            "SELECT * FROM oauth_providers WHERE provider_name = ? AND provider_user_id = ?",
        )
        .bind(provider_name.as_str())
        .bind(provider_user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(provider)
    }

    pub async fn update_tokens(
        &self,
        id: &str,
        access_token_encrypted: &str,
        refresh_token_encrypted: Option<&str>,
        token_expires_at: Option<&str>,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            r"
            UPDATE oauth_providers
            SET access_token_encrypted = ?, refresh_token_encrypted = ?, token_expires_at = ?, updated_at = ?
            WHERE id = ?
            ",
        )
        .bind(access_token_encrypted)
        .bind(refresh_token_encrypted)
        .bind(token_expires_at)
        .bind(&now)
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn delete_by_user_id(&self, user_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM oauth_providers WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn upsert(&self, provider: &OAuthProvider) -> Result<()> {
        let provider_name = provider
            .provider_name
            .parse()
            .map_err(|_| crate::error::AppError::BadRequest("Invalid provider name".to_string()))?;
        let existing = self
            .find_by_provider_user(provider_name, &provider.provider_user_id)
            .await?;

        if let Some(existing) = existing {
            self.update_tokens(
                &existing.id,
                provider.access_token_encrypted.as_deref().unwrap_or(""),
                provider.refresh_token_encrypted.as_deref(),
                provider.token_expires_at.as_deref(),
            )
            .await?;
        } else {
            self.create(provider).await?;
        }

        Ok(())
    }
}
