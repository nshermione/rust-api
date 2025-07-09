use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

// User registration request
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub full_name: Option<String>,
}

// User login request
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

// Authentication response
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub token_type: String,
    pub expires_in: i64, // seconds
    pub user: UserDto,
}

// User profile response
#[derive(Debug, Serialize, Clone)]
pub struct UserDto {
    pub id: String,
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
    pub role: UserRole,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
}

// User role enum
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum UserRole {
    Admin,
    User,
    Guest,
}

impl Default for UserRole {
    fn default() -> Self {
        UserRole::User
    }
}

impl UserRole {
    pub fn to_string(&self) -> String {
        match self {
            UserRole::Admin => "admin".to_string(),
            UserRole::User => "user".to_string(),
            UserRole::Guest => "guest".to_string(),
        }
    }

    pub fn from_string(role: &str) -> Result<Self, String> {
        match role.to_lowercase().as_str() {
            "admin" => Ok(UserRole::Admin),
            "user" => Ok(UserRole::User),
            "guest" => Ok(UserRole::Guest),
            _ => Err(format!("Invalid role: {}", role)),
        }
    }

    pub fn has_permission(&self, required_role: &UserRole) -> bool {
        match (self, required_role) {
            (UserRole::Admin, _) => true, // Admin has all permissions
            (UserRole::User, UserRole::User | UserRole::Guest) => true,
            (UserRole::Guest, UserRole::Guest) => true,
            _ => false,
        }
    }
}

// JWT Claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,        // Subject (user ID)
    pub username: String,   // Username
    pub role: String,       // User role
    pub locale: Option<String>, // User preferred locale
    pub exp: usize,         // Expiration time (timestamp)
    pub iat: usize,         // Issued at (timestamp)
    pub iss: String,        // Issuer
}

impl Claims {
    pub fn new(user_id: Uuid, username: String, role: UserRole, locale: Option<String>, expires_in_hours: i64) -> Self {
        let now = Utc::now();
        let exp = (now + chrono::Duration::hours(expires_in_hours)).timestamp() as usize;
        
        Self {
            sub: user_id.to_string(),
            username,
            role: role.to_string(),
            locale,
            exp,
            iat: now.timestamp() as usize,
            iss: "rust-api-service".to_string(),
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = Utc::now().timestamp() as usize;
        now >= self.exp
    }

    pub fn get_role(&self) -> Result<UserRole, String> {
        UserRole::from_string(&self.role)
    }

    pub fn get_user_id(&self) -> Result<Uuid, uuid::Error> {
        Uuid::parse_str(&self.sub)
    }
}

// Password change request
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

// User update request
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub full_name: Option<String>,
    pub email: Option<String>,
}

// Token validation response
#[derive(Debug, Serialize)]
pub struct TokenValidationResponse {
    pub valid: bool,
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub role: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

// Error responses
#[derive(Debug, Serialize)]
pub struct AuthErrorResponse {
    pub error: String,
    pub message: String,
    pub details: Option<String>,
}

impl AuthErrorResponse {
    pub fn new(error: &str, message: &str) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
            details: None,
        }
    }

    pub fn with_details(error: &str, message: &str, details: &str) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
            details: Some(details.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_role_permissions() {
        let admin = UserRole::Admin;
        let user = UserRole::User;
        let guest = UserRole::Guest;

        // Admin has all permissions
        assert!(admin.has_permission(&UserRole::Admin));
        assert!(admin.has_permission(&UserRole::User));
        assert!(admin.has_permission(&UserRole::Guest));

        // User has user and guest permissions
        assert!(!user.has_permission(&UserRole::Admin));
        assert!(user.has_permission(&UserRole::User));
        assert!(user.has_permission(&UserRole::Guest));

        // Guest only has guest permissions
        assert!(!guest.has_permission(&UserRole::Admin));
        assert!(!guest.has_permission(&UserRole::User));
        assert!(guest.has_permission(&UserRole::Guest));
    }

    #[test]
    fn test_claims_creation() {
        let user_id = Uuid::new_v4();
        let claims = Claims::new(
            user_id,
            "testuser".to_string(),
            UserRole::User,
            Some("en".to_string()),
            24
        );

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.username, "testuser");
        assert_eq!(claims.role, "user");
        assert_eq!(claims.locale, Some("en".to_string()));
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_role_serialization() {
        assert_eq!(UserRole::Admin.to_string(), "admin");
        assert_eq!(UserRole::User.to_string(), "user");
        assert_eq!(UserRole::Guest.to_string(), "guest");

        assert_eq!(UserRole::from_string("admin").unwrap(), UserRole::Admin);
        assert_eq!(UserRole::from_string("user").unwrap(), UserRole::User);
        assert_eq!(UserRole::from_string("guest").unwrap(), UserRole::Guest);
        assert!(UserRole::from_string("invalid").is_err());
    }
} 