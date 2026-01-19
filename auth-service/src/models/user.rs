use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub profile_picture_url: Option<String>,
    pub is_active: bool,
    pub email_verified: bool,
    pub created_at: String,
    pub updated_at: String,
    pub last_login_at: Option<String>,
}

impl User {
    pub fn new(email: String, display_name: Option<String>, profile_picture_url: Option<String>) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            id: Uuid::new_v4().to_string(),
            email,
            display_name,
            profile_picture_url,
            is_active: true,
            email_verified: false,
            created_at: now.clone(),
            updated_at: now,
            last_login_at: None,
        }
    }

    pub fn with_email_verified(mut self) -> Self {
        self.email_verified = true;
        self
    }
}

#[derive(Debug, Serialize)]
pub struct UserProfile {
    pub id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub profile_picture_url: Option<String>,
    pub email_verified: bool,
    pub created_at: String,
}

impl From<User> for UserProfile {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            display_name: user.display_name,
            profile_picture_url: user.profile_picture_url,
            email_verified: user.email_verified,
            created_at: user.created_at,
        }
    }
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserRequest {
    #[validate(length(min = 1, max = 255))]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CreateUserFromOAuth {
    pub email: String,
    pub display_name: Option<String>,
    pub profile_picture_url: Option<String>,
    pub email_verified: bool,
}
