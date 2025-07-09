use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use bson::oid::ObjectId;

use crate::domains::user::dto::UserRole;

// User model for database storage
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub user_id: String,        // UUID as string
    pub username: String,
    pub email: String,
    pub password_hash: String,  // Bcrypt hash
    pub full_name: Option<String>,
    pub role: UserRole,
    pub is_active: bool,
    pub is_verified: bool,
    pub preferred_locale: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub failed_login_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
}

impl User {
    pub fn new(username: String, email: String, password_hash: String, full_name: Option<String>) -> Self {
        let now = Utc::now();
        
        Self {
            id: None,
            user_id: Uuid::new_v4().to_string(),
            username,
            email,
            password_hash,
            full_name,
            role: UserRole::default(),
            is_active: true,
            is_verified: false,
            preferred_locale: Some("en".to_string()),
            created_at: now,
            updated_at: now,
            last_login: None,
            failed_login_attempts: 0,
            locked_until: None,
        }
    }

    pub fn get_user_id(&self) -> Result<Uuid, uuid::Error> {
        Uuid::parse_str(&self.user_id)
    }

    pub fn update_last_login(&mut self) {
        self.last_login = Some(Utc::now());
        self.updated_at = Utc::now();
        self.failed_login_attempts = 0; // Reset failed attempts on successful login
    }

    pub fn increment_failed_login(&mut self) {
        self.failed_login_attempts += 1;
        self.updated_at = Utc::now();
        
        // Lock account after 5 failed attempts for 15 minutes
        if self.failed_login_attempts >= 5 {
            self.locked_until = Some(Utc::now() + chrono::Duration::minutes(15));
        }
    }

    pub fn is_locked(&self) -> bool {
        if let Some(locked_until) = self.locked_until {
            Utc::now() < locked_until
        } else {
            false
        }
    }

    pub fn unlock_account(&mut self) {
        self.failed_login_attempts = 0;
        self.locked_until = None;
        self.updated_at = Utc::now();
    }

    pub fn change_password(&mut self, new_password_hash: String) {
        self.password_hash = new_password_hash;
        self.updated_at = Utc::now();
    }

    pub fn update_profile(&mut self, full_name: Option<String>, email: Option<String>) {
        if let Some(name) = full_name {
            self.full_name = Some(name);
        }
        if let Some(new_email) = email {
            self.email = new_email;
        }
        self.updated_at = Utc::now();
    }

    pub fn set_verified(&mut self) {
        self.is_verified = true;
        self.updated_at = Utc::now();
    }

    pub fn deactivate(&mut self) {
        self.is_active = false;
        self.updated_at = Utc::now();
    }

    pub fn activate(&mut self) {
        self.is_active = true;
        self.updated_at = Utc::now();
    }

    pub fn set_role(&mut self, role: UserRole) {
        self.role = role;
        self.updated_at = Utc::now();
    }

    pub fn set_locale(&mut self, locale: String) {
        self.preferred_locale = Some(locale);
        self.updated_at = Utc::now();
    }
}

impl From<&User> for crate::domains::user::dto::UserDto {
    fn from(user: &User) -> Self {
        Self {
            id: user.user_id.clone(),
            username: user.username.clone(),
            email: user.email.clone(),
            full_name: user.full_name.clone(),
            role: user.role.clone(),
            is_active: user.is_active,
            created_at: user.created_at,
            last_login: user.last_login,
        }
    }
}

// Session model for tracking active sessions
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserSession {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub session_id: String,     // UUID as string
    pub user_id: String,        // User UUID
    pub token_jti: String,      // JWT ID for token invalidation
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_active: bool,
}

impl UserSession {
    pub fn new(user_id: String, token_jti: String, expires_at: DateTime<Utc>) -> Self {
        Self {
            id: None,
            session_id: Uuid::new_v4().to_string(),
            user_id,
            token_jti,
            ip_address: None,
            user_agent: None,
            created_at: Utc::now(),
            expires_at,
            is_active: true,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    pub fn invalidate(&mut self) {
        self.is_active = false;
    }

    pub fn set_client_info(&mut self, ip_address: Option<String>, user_agent: Option<String>) {
        self.ip_address = ip_address;
        self.user_agent = user_agent;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_creation() {
        let user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            "hashed_password".to_string(),
            Some("Test User".to_string()),
        );

        assert_eq!(user.username, "testuser");
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.role, UserRole::User);
        assert!(user.is_active);
        assert!(!user.is_verified);
        assert_eq!(user.failed_login_attempts, 0);
        assert!(!user.is_locked());
    }

    #[test]
    fn test_failed_login_attempts() {
        let mut user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            "hashed_password".to_string(),
            None,
        );

        // Test failed login attempts
        for _ in 0..4 {
            user.increment_failed_login();
            assert!(!user.is_locked());
        }

        // 5th failed attempt should lock the account
        user.increment_failed_login();
        assert!(user.is_locked());
        assert_eq!(user.failed_login_attempts, 5);

        // Unlock account
        user.unlock_account();
        assert!(!user.is_locked());
        assert_eq!(user.failed_login_attempts, 0);
    }

    #[test]
    fn test_user_session() {
        let user_id = Uuid::new_v4().to_string();
        let token_jti = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + chrono::Duration::hours(24);

        let mut session = UserSession::new(user_id.clone(), token_jti.clone(), expires_at);

        assert_eq!(session.user_id, user_id);
        assert_eq!(session.token_jti, token_jti);
        assert!(session.is_active);
        assert!(!session.is_expired());

        session.invalidate();
        assert!(!session.is_active);
    }

    #[test]
    fn test_user_dto_conversion() {
        let user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            "hashed_password".to_string(),
            Some("Test User".to_string()),
        );

        let user_dto: crate::domains::user::dto::UserDto = (&user).into();

        assert_eq!(user_dto.id, user.user_id);
        assert_eq!(user_dto.username, user.username);
        assert_eq!(user_dto.email, user.email);
        assert_eq!(user_dto.full_name, user.full_name);
        assert_eq!(user_dto.role, user.role);
    }
} 