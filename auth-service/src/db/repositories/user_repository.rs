use chrono::Utc;
use sqlx::SqlitePool;

use crate::error::Result;
use crate::models::{CreateUserFromOAuth, User};

pub struct UserRepository {
    pool: SqlitePool,
}

impl UserRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, user: &User) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO users (id, email, display_name, profile_picture_url, is_active, email_verified, created_at, updated_at, last_login_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&user.id)
        .bind(&user.email)
        .bind(&user.display_name)
        .bind(&user.profile_picture_url)
        .bind(user.is_active)
        .bind(user.email_verified)
        .bind(&user.created_at)
        .bind(&user.updated_at)
        .bind(&user.last_login_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(user)
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = ?")
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;

        Ok(user)
    }

    pub async fn update_display_name(&self, id: &str, display_name: Option<&str>) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query("UPDATE users SET display_name = ?, updated_at = ? WHERE id = ?")
            .bind(display_name)
            .bind(&now)
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn update_last_login(&self, id: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query("UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?")
            .bind(&now)
            .bind(&now)
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn deactivate(&self, id: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query("UPDATE users SET is_active = 0, updated_at = ? WHERE id = ?")
            .bind(&now)
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn delete(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn find_or_create_from_oauth(&self, data: &CreateUserFromOAuth) -> Result<User> {
        if let Some(existing) = self.find_by_email(&data.email).await? {
            return Ok(existing);
        }

        let user = User::new(
            data.email.clone(),
            data.display_name.clone(),
            data.profile_picture_url.clone(),
        );

        let user = if data.email_verified {
            user.with_email_verified()
        } else {
            user
        };

        self.create(&user).await?;
        Ok(user)
    }
}
