use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::Arc;

/// Result of anomaly detection check
#[derive(Debug, Clone, PartialEq)]
pub enum AnomalyResult {
    /// No anomaly detected
    Normal,
    /// Too many failed login attempts - account should be temporarily locked
    BruteForceDetected {
        attempts: u32,
        lockout_until: DateTime<Utc>,
    },
    /// Login from unusual location
    UnusualLocation {
        previous_ip: String,
        current_ip: String,
    },
    /// Impossible travel detected (login from far locations in short time)
    ImpossibleTravel {
        previous_location: String,
        current_location: String,
        time_diff_minutes: i64,
    },
    /// Unusual activity pattern
    UnusualPattern { reason: String },
}

impl AnomalyResult {
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        matches!(self, AnomalyResult::BruteForceDetected { .. })
    }

    #[must_use]
    pub fn should_warn(&self) -> bool {
        !matches!(self, AnomalyResult::Normal)
    }
}

/// Configuration for anomaly detection
#[derive(Debug, Clone)]
pub struct AnomalyConfig {
    /// Maximum failed login attempts before lockout
    pub max_failed_attempts: u32,
    /// Lockout duration in minutes after max failed attempts
    pub lockout_duration_minutes: i64,
    /// Time window for counting failed attempts (in minutes)
    pub failed_attempt_window_minutes: i64,
    /// Minimum time (in minutes) that would be suspicious for location change
    pub suspicious_travel_time_minutes: i64,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            max_failed_attempts: 5,
            lockout_duration_minutes: 15,
            failed_attempt_window_minutes: 30,
            suspicious_travel_time_minutes: 60, // 1 hour
        }
    }
}

/// Tracks login attempts for an IP address
#[derive(Debug, Clone, Default)]
struct IpLoginAttempts {
    failed_attempts: VecDeque<DateTime<Utc>>,
    lockout_until: Option<DateTime<Utc>>,
}

/// Tracks user login history for anomaly detection
#[derive(Debug, Clone)]
struct UserLoginHistory {
    /// Recent login locations (IP addresses)
    recent_logins: VecDeque<LoginRecord>,
    /// Known IPs for this user
    known_ips: Vec<String>,
}

#[derive(Debug, Clone)]
struct LoginRecord {
    ip: String,
    ip_subnet: String,
    timestamp: DateTime<Utc>,
    #[allow(dead_code)]
    user_agent: Option<String>,
}

impl Default for UserLoginHistory {
    fn default() -> Self {
        Self {
            recent_logins: VecDeque::with_capacity(10),
            known_ips: Vec::new(),
        }
    }
}

/// Service for detecting suspicious login activity
pub struct AnomalyDetectionService {
    config: AnomalyConfig,
    /// Failed login attempts per IP
    ip_attempts: Arc<DashMap<String, IpLoginAttempts>>,
    /// Login history per user
    user_history: Arc<DashMap<String, UserLoginHistory>>,
}

impl AnomalyDetectionService {
    #[must_use]
    pub fn new(config: AnomalyConfig) -> Self {
        Self {
            config,
            ip_attempts: Arc::new(DashMap::new()),
            user_history: Arc::new(DashMap::new()),
        }
    }

    /// Check if an IP is currently locked out due to brute force attempts
    #[must_use]
    pub fn check_ip_lockout(&self, ip: &str) -> Option<AnomalyResult> {
        if let Some(attempts) = self.ip_attempts.get(ip) {
            if let Some(lockout_until) = attempts.lockout_until {
                if Utc::now() < lockout_until {
                    return Some(AnomalyResult::BruteForceDetected {
                        attempts: u32::try_from(attempts.failed_attempts.len()).unwrap_or(u32::MAX),
                        lockout_until,
                    });
                }
            }
        }
        None
    }

    /// Record a failed login attempt from an IP
    #[must_use]
    pub fn record_failed_attempt(&self, ip: &str) -> AnomalyResult {
        let now = Utc::now();
        let window_start = now - Duration::minutes(self.config.failed_attempt_window_minutes);

        let mut entry = self.ip_attempts.entry(ip.to_string()).or_default();

        // Remove old attempts outside the window
        while entry
            .failed_attempts
            .front()
            .is_some_and(|t| *t < window_start)
        {
            entry.failed_attempts.pop_front();
        }

        // Add new attempt
        entry.failed_attempts.push_back(now);

        let attempt_count = u32::try_from(entry.failed_attempts.len()).unwrap_or(u32::MAX);

        // Check if we've exceeded the threshold
        if attempt_count >= self.config.max_failed_attempts {
            let lockout_until = now + Duration::minutes(self.config.lockout_duration_minutes);
            entry.lockout_until = Some(lockout_until);

            tracing::warn!(
                ip = %ip,
                attempts = attempt_count,
                lockout_until = %lockout_until,
                "Brute force attack detected - IP locked out"
            );

            return AnomalyResult::BruteForceDetected {
                attempts: attempt_count,
                lockout_until,
            };
        }

        AnomalyResult::Normal
    }

    /// Clear failed attempts for an IP (called on successful login)
    pub fn clear_failed_attempts(&self, ip: &str) {
        if let Some(mut entry) = self.ip_attempts.get_mut(ip) {
            entry.failed_attempts.clear();
            entry.lockout_until = None;
        }
    }

    /// Check for login anomalies for a user
    #[must_use]
    pub fn check_login_anomaly(
        &self,
        user_id: &str,
        ip: &str,
        _user_agent: Option<&str>,
    ) -> AnomalyResult {
        let now = Utc::now();
        let ip_subnet = extract_ip_subnet(ip);

        let mut entry = self.user_history.entry(user_id.to_string()).or_default();

        // Check for impossible travel
        if let Some(last_login) = entry.recent_logins.back() {
            let time_diff = now.signed_duration_since(last_login.timestamp);
            let time_diff_minutes = time_diff.num_minutes();

            // If login from different subnet within suspicious time window
            if last_login.ip_subnet != ip_subnet
                && time_diff_minutes < self.config.suspicious_travel_time_minutes
                && time_diff_minutes > 0
            {
                tracing::warn!(
                    user_id = %user_id,
                    previous_ip = %last_login.ip,
                    current_ip = %ip,
                    time_diff_minutes = time_diff_minutes,
                    "Suspicious location change detected"
                );

                // Still allow login but flag as suspicious
                return AnomalyResult::ImpossibleTravel {
                    previous_location: last_login.ip_subnet.clone(),
                    current_location: ip_subnet.clone(),
                    time_diff_minutes,
                };
            }
        }

        // Check for unusual location (IP not in known IPs)
        let is_new_ip = !entry.known_ips.contains(&ip.to_string());

        if is_new_ip && !entry.known_ips.is_empty() {
            let previous_ip = entry.known_ips.last().cloned().unwrap_or_default();

            tracing::info!(
                user_id = %user_id,
                new_ip = %ip,
                "Login from new IP address"
            );

            // Add to known IPs (keep last 10)
            if entry.known_ips.len() >= 10 {
                entry.known_ips.remove(0);
            }
            entry.known_ips.push(ip.to_string());

            return AnomalyResult::UnusualLocation {
                previous_ip,
                current_ip: ip.to_string(),
            };
        }

        // Add IP to known IPs if new
        if is_new_ip {
            entry.known_ips.push(ip.to_string());
        }

        AnomalyResult::Normal
    }

    /// Record a successful login
    pub fn record_successful_login(&self, user_id: &str, ip: &str, user_agent: Option<&str>) {
        let now = Utc::now();
        let ip_subnet = extract_ip_subnet(ip);

        let mut entry = self.user_history.entry(user_id.to_string()).or_default();

        // Add login record
        let record = LoginRecord {
            ip: ip.to_string(),
            ip_subnet,
            timestamp: now,
            user_agent: user_agent.map(String::from),
        };

        entry.recent_logins.push_back(record);

        // Keep only last 10 logins
        while entry.recent_logins.len() > 10 {
            entry.recent_logins.pop_front();
        }

        // Update known IPs
        if !entry.known_ips.contains(&ip.to_string()) {
            if entry.known_ips.len() >= 10 {
                entry.known_ips.remove(0);
            }
            entry.known_ips.push(ip.to_string());
        }

        // Clear any failed attempts for this IP
        self.clear_failed_attempts(ip);
    }

    /// Cleanup old data periodically
    pub fn cleanup(&self) {
        let now = Utc::now();
        let window = Duration::hours(24);

        // Remove old IP attempts
        self.ip_attempts.retain(|_, attempts| {
            // Keep if there are recent attempts or active lockout
            if let Some(lockout) = attempts.lockout_until {
                if now < lockout {
                    return true;
                }
            }

            attempts
                .failed_attempts
                .iter()
                .any(|t| now.signed_duration_since(*t) < window)
        });

        tracing::debug!("Anomaly detection cleanup completed");
    }
}

impl Clone for AnomalyDetectionService {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            ip_attempts: Arc::clone(&self.ip_attempts),
            user_history: Arc::clone(&self.user_history),
        }
    }
}

/// Extract subnet from IP address (for privacy-preserving comparison)
fn extract_ip_subnet(ip: &str) -> String {
    if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
        match addr {
            std::net::IpAddr::V4(v4) => {
                let octets = v4.octets();
                format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
            }
            std::net::IpAddr::V6(v6) => {
                let segments = v6.segments();
                format!("{:x}:{:x}:{:x}::/48", segments[0], segments[1], segments[2])
            }
        }
    } else {
        ip.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_brute_force_detection() {
        let config = AnomalyConfig {
            max_failed_attempts: 3,
            lockout_duration_minutes: 15,
            ..Default::default()
        };
        let service = AnomalyDetectionService::new(config);

        let ip = "192.168.1.1";

        // First two attempts should be normal
        assert_eq!(service.record_failed_attempt(ip), AnomalyResult::Normal);
        assert_eq!(service.record_failed_attempt(ip), AnomalyResult::Normal);

        // Third attempt should trigger lockout
        let result = service.record_failed_attempt(ip);
        assert!(matches!(result, AnomalyResult::BruteForceDetected { .. }));

        // Should be locked out
        assert!(service.check_ip_lockout(ip).is_some());
    }

    #[test]
    fn test_clear_failed_attempts() {
        let service = AnomalyDetectionService::new(AnomalyConfig::default());
        let ip = "192.168.1.1";

        let _ = service.record_failed_attempt(ip);
        let _ = service.record_failed_attempt(ip);
        service.clear_failed_attempts(ip);

        // Should be able to fail again without immediate lockout
        assert_eq!(service.record_failed_attempt(ip), AnomalyResult::Normal);
    }

    #[test]
    fn test_extract_ip_subnet() {
        assert_eq!(extract_ip_subnet("192.168.1.100"), "192.168.1.0/24");
        assert_eq!(extract_ip_subnet("10.0.0.1"), "10.0.0.0/24");
    }
}
