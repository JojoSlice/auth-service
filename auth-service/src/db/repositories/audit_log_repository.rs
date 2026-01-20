use sqlx::SqlitePool;

use crate::error::Result;
use crate::models::AuditLog;

pub struct AuditLogRepository {
    pool: SqlitePool,
}

impl AuditLogRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, log: &AuditLog) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO audit_logs (id, timestamp, event_type, user_id, ip_address, user_agent, request_id, endpoint, http_method, status_code, error_message, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&log.id)
        .bind(&log.timestamp)
        .bind(&log.event_type)
        .bind(&log.user_id)
        .bind(&log.ip_address)
        .bind(&log.user_agent)
        .bind(&log.request_id)
        .bind(&log.endpoint)
        .bind(&log.http_method)
        .bind(&log.status_code)
        .bind(&log.error_message)
        .bind(&log.metadata)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<AuditLog>> {
        let log = sqlx::query_as::<_, AuditLog>("SELECT * FROM audit_logs WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(log)
    }

    pub async fn find_by_user_id(&self, user_id: &str, limit: i64) -> Result<Vec<AuditLog>> {
        let logs = sqlx::query_as::<_, AuditLog>(
            "SELECT * FROM audit_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(logs)
    }

    pub async fn find_by_ip_address(&self, ip_address: &str, limit: i64) -> Result<Vec<AuditLog>> {
        let logs = sqlx::query_as::<_, AuditLog>(
            "SELECT * FROM audit_logs WHERE ip_address = ? ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(ip_address)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(logs)
    }

    pub async fn find_by_event_type(&self, event_type: &str, limit: i64) -> Result<Vec<AuditLog>> {
        let logs = sqlx::query_as::<_, AuditLog>(
            "SELECT * FROM audit_logs WHERE event_type = ? ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(event_type)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(logs)
    }

    pub async fn find_by_request_id(&self, request_id: &str) -> Result<Vec<AuditLog>> {
        let logs = sqlx::query_as::<_, AuditLog>(
            "SELECT * FROM audit_logs WHERE request_id = ? ORDER BY timestamp",
        )
        .bind(request_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(logs)
    }

    pub async fn find_recent(&self, limit: i64) -> Result<Vec<AuditLog>> {
        let logs = sqlx::query_as::<_, AuditLog>(
            "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(logs)
    }

    pub async fn delete_older_than(&self, before_timestamp: &str) -> Result<u64> {
        let result = sqlx::query("DELETE FROM audit_logs WHERE timestamp < ?")
            .bind(before_timestamp)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }
}
