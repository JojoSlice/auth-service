use chrono::Utc;
use sqlx::SqlitePool;

use crate::error::Result;
use crate::models::{FilterType, IpFilter};

pub struct IpFilterRepository {
    pool: SqlitePool,
}

impl IpFilterRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, filter: &IpFilter) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO ip_filters (id, ip_address, filter_type, reason, is_active, expires_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&filter.id)
        .bind(&filter.ip_address)
        .bind(&filter.filter_type)
        .bind(&filter.reason)
        .bind(filter.is_active)
        .bind(&filter.expires_at)
        .bind(&filter.created_at)
        .bind(&filter.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<IpFilter>> {
        let filter = sqlx::query_as::<_, IpFilter>("SELECT * FROM ip_filters WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(filter)
    }

    pub async fn find_by_ip(&self, ip_address: &str) -> Result<Vec<IpFilter>> {
        let filters = sqlx::query_as::<_, IpFilter>(
            "SELECT * FROM ip_filters WHERE ip_address = ? AND is_active = 1",
        )
        .bind(ip_address)
        .fetch_all(&self.pool)
        .await?;

        Ok(filters)
    }

    pub async fn is_blacklisted(&self, ip_address: &str) -> Result<bool> {
        let filter = sqlx::query_as::<_, IpFilter>(
            "SELECT * FROM ip_filters WHERE ip_address = ? AND filter_type = ? AND is_active = 1",
        )
        .bind(ip_address)
        .bind(FilterType::Blacklist.as_str())
        .fetch_optional(&self.pool)
        .await?;

        if let Some(filter) = filter {
            if filter.is_expired() {
                self.deactivate(&filter.id).await?;
                return Ok(false);
            }
            return Ok(true);
        }

        Ok(false)
    }

    pub async fn is_whitelisted(&self, ip_address: &str) -> Result<bool> {
        let filter = sqlx::query_as::<_, IpFilter>(
            "SELECT * FROM ip_filters WHERE ip_address = ? AND filter_type = ? AND is_active = 1",
        )
        .bind(ip_address)
        .bind(FilterType::Whitelist.as_str())
        .fetch_optional(&self.pool)
        .await?;

        if let Some(filter) = filter {
            if filter.is_expired() {
                self.deactivate(&filter.id).await?;
                return Ok(false);
            }
            return Ok(true);
        }

        Ok(false)
    }

    pub async fn list_by_type(&self, filter_type: FilterType) -> Result<Vec<IpFilter>> {
        let filters = sqlx::query_as::<_, IpFilter>(
            "SELECT * FROM ip_filters WHERE filter_type = ? AND is_active = 1",
        )
        .bind(filter_type.as_str())
        .fetch_all(&self.pool)
        .await?;

        Ok(filters)
    }

    pub async fn deactivate(&self, id: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query("UPDATE ip_filters SET is_active = 0, updated_at = ? WHERE id = ?")
            .bind(&now)
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn delete(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM ip_filters WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn cleanup_expired(&self) -> Result<u64> {
        let now = Utc::now().to_rfc3339();
        let result = sqlx::query(
            "UPDATE ip_filters SET is_active = 0, updated_at = ? WHERE expires_at IS NOT NULL AND expires_at < ? AND is_active = 1",
        )
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }
}
