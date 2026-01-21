use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilterType {
    Whitelist,
    Blacklist,
}

impl FilterType {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            FilterType::Whitelist => "whitelist",
            FilterType::Blacklist => "blacklist",
        }
    }
}

impl std::fmt::Display for FilterType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for FilterType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "whitelist" => Ok(FilterType::Whitelist),
            "blacklist" => Ok(FilterType::Blacklist),
            _ => Err(format!("Unknown filter type: {s}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IpFilter {
    pub id: String,
    pub ip_address: String,
    pub filter_type: String,
    pub reason: Option<String>,
    pub is_active: bool,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl IpFilter {
    #[must_use]
    pub fn new(ip_address: String, filter_type: FilterType, reason: Option<String>) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            id: Uuid::new_v4().to_string(),
            ip_address,
            filter_type: filter_type.to_string(),
            reason,
            is_active: true,
            expires_at: None,
            created_at: now.clone(),
            updated_at: now,
        }
    }

    #[must_use]
    pub fn with_expiration(mut self, expires_at: String) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = &self.expires_at {
            if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires_at) {
                return exp < Utc::now();
            }
        }
        false
    }

    #[must_use]
    pub fn get_filter_type(&self) -> Option<FilterType> {
        self.filter_type.parse().ok()
    }
}
