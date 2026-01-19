use chrono::Utc;
use sqlx::SqlitePool;

use crate::error::Result;
use crate::models::ApiKey;

pub struct ApiKeyRepository {
    pool: SqlitePool,
}

impl ApiKeyRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, api_key: &ApiKey) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO api_keys (id, key_hash, key_prefix, name, client_project, allowed_origins, is_active, rate_limit_per_minute, expires_at, created_at, updated_at, last_used_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&api_key.id)
        .bind(&api_key.key_hash)
        .bind(&api_key.key_prefix)
        .bind(&api_key.name)
        .bind(&api_key.client_project)
        .bind(&api_key.allowed_origins)
        .bind(api_key.is_active)
        .bind(api_key.rate_limit_per_minute)
        .bind(&api_key.expires_at)
        .bind(&api_key.created_at)
        .bind(&api_key.updated_at)
        .bind(&api_key.last_used_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<ApiKey>> {
        let key = sqlx::query_as::<_, ApiKey>("SELECT * FROM api_keys WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(key)
    }

    pub async fn find_by_key_hash(&self, key_hash: &str) -> Result<Option<ApiKey>> {
        let key = sqlx::query_as::<_, ApiKey>(
            "SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1",
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(key)
    }

    pub async fn find_by_prefix(&self, prefix: &str) -> Result<Vec<ApiKey>> {
        let keys = sqlx::query_as::<_, ApiKey>("SELECT * FROM api_keys WHERE key_prefix = ?")
            .bind(prefix)
            .fetch_all(&self.pool)
            .await?;

        Ok(keys)
    }

    pub async fn find_active_by_project(&self, client_project: &str) -> Result<Vec<ApiKey>> {
        let keys = sqlx::query_as::<_, ApiKey>(
            "SELECT * FROM api_keys WHERE client_project = ? AND is_active = 1",
        )
        .bind(client_project)
        .fetch_all(&self.pool)
        .await?;

        Ok(keys)
    }

    pub async fn update_last_used(&self, id: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query("UPDATE api_keys SET last_used_at = ? WHERE id = ?")
            .bind(&now)
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn deactivate(&self, id: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query("UPDATE api_keys SET is_active = 0, updated_at = ? WHERE id = ?")
            .bind(&now)
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn delete(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM api_keys WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn list_all(&self) -> Result<Vec<ApiKey>> {
        let keys = sqlx::query_as::<_, ApiKey>("SELECT * FROM api_keys ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await?;

        Ok(keys)
    }
}
