use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use crate::shared::utils::date_util::{DateTime, DateUtil, Duration};
use uuid::Uuid;
use std::collections::HashSet;

use crate::domains::user::dto::{Claims, UserRole, TokenValidationResponse};
use crate::shared::models::User;

#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("Token creation failed: {0}")]
    TokenCreation(String),
    #[error("Token validation failed: {0}")]
    TokenValidation(String),
    #[error("Token expired")]
    TokenExpired,
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    #[error("Missing token")]
    MissingToken,
}

#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub algorithm: Algorithm,
    pub token_expiry_hours: i64,
    pub refresh_token_expiry_days: i64,
    pub issuer: String,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: "your-secret-key".to_string(), // Should be loaded from config
            algorithm: Algorithm::HS256,
            token_expiry_hours: 24,
            refresh_token_expiry_days: 30,
            issuer: "rust-api-service".to_string(),
        }
    }
}

pub struct JwtService {
    config: JwtConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtService {
    pub fn new(config: JwtConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(config.secret.as_ref());
        let decoding_key = DecodingKey::from_secret(config.secret.as_ref());
        
        let mut validation = Validation::new(config.algorithm);
        validation.set_issuer(&[&config.issuer]);
        
        Self {
            config,
            encoding_key,
            decoding_key,
            validation,
        }
    }

    // Generate access token for user
    pub fn generate_token(&self, user: &User) -> Result<(String, DateTime), JwtError> {
        let expires_at = DateUtil::add_duration(&DateUtil::now(), DateUtil::hours(self.config.token_expiry_hours))
            .map_err(|e| JwtError::TokenCreation(e.to_string()))?;
        
        let now = DateUtil::now();
        let claims = crate::domains::user::dto::Claims {
            sub: user.user_id.clone(),
            username: user.username.clone(),
            role: user.role.to_string(),
            locale: user.preferred_locale.clone(),
            exp: DateUtil::to_timestamp(&DateUtil::add_duration(&now, DateUtil::hours(self.config.token_expiry_hours)).unwrap()) as usize,
            iat: DateUtil::to_timestamp(&now) as usize,
            iss: self.config.issuer.clone(),
        };

        let token = encode(&Header::new(self.config.algorithm), &claims, &self.encoding_key)
            .map_err(|e| JwtError::TokenCreation(e.to_string()))?;

        Ok((token, expires_at))
    }

    // Generate refresh token (longer expiry, different claims)
    pub fn generate_refresh_token(&self, user: &User) -> Result<(String, DateTime), JwtError> {
        let expires_at = DateUtil::add_duration(&DateUtil::now(), DateUtil::days(self.config.refresh_token_expiry_days))
            .map_err(|e| JwtError::TokenCreation(e.to_string()))?;
        
        let refresh_claims = RefreshTokenClaims {
            sub: user.user_id.clone(),
            jti: Uuid::new_v4().to_string(), // Unique JWT ID for tracking
            exp: DateUtil::to_timestamp(&expires_at) as usize,
            iat: DateUtil::to_timestamp(&DateUtil::now()) as usize,
            iss: self.config.issuer.clone(),
            token_type: "refresh".to_string(),
        };

        let token = encode(&Header::new(self.config.algorithm), &refresh_claims, &self.encoding_key)
            .map_err(|e| JwtError::TokenCreation(e.to_string()))?;

        Ok((token, expires_at))
    }

    // Validate and decode access token
    pub fn validate_token(&self, token: &str) -> Result<Claims, JwtError> {
        let token_data = decode::<Claims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::TokenExpired,
                _ => JwtError::TokenValidation(e.to_string()),
            })?;

        let claims = token_data.claims;
        
        // Additional validation
        if claims.is_expired() {
            return Err(JwtError::TokenExpired);
        }

        Ok(claims)
    }

    // Validate refresh token
    pub fn validate_refresh_token(&self, token: &str) -> Result<RefreshTokenClaims, JwtError> {
        let token_data = decode::<RefreshTokenClaims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::TokenExpired,
                _ => JwtError::TokenValidation(e.to_string()),
            })?;

        let claims = token_data.claims;
        
        if claims.is_expired() {
            return Err(JwtError::TokenExpired);
        }

        Ok(claims)
    }

    // Extract token from Authorization header
    pub fn extract_token_from_header(&self, auth_header: &str) -> Result<String, JwtError> {
        if !auth_header.starts_with("Bearer ") {
            return Err(JwtError::InvalidToken("Invalid authorization header format".to_string()));
        }

        let token = auth_header.strip_prefix("Bearer ").unwrap_or(auth_header);
        
        if token.is_empty() {
            return Err(JwtError::MissingToken);
        }

        Ok(token.to_string())
    }

    // Get token validation response (for API endpoints)
    pub fn get_token_validation_response(&self, token: &str) -> TokenValidationResponse {
        match self.validate_token(token) {
            Ok(claims) => TokenValidationResponse {
                valid: true,
                user_id: Some(claims.sub),
                username: Some(claims.username),
                role: Some(claims.role),
                expires_at: Some(DateUtil::from_timestamp(claims.exp as i64).unwrap_or_default()),
            },
            Err(_) => TokenValidationResponse {
                valid: false,
                user_id: None,
                username: None,
                role: None,
                expires_at: None,
            },
        }
    }

    // Check if user has required role
    pub fn check_role_permission(&self, token: &str, required_role: UserRole) -> Result<bool, JwtError> {
        let claims = self.validate_token(token)?;
        let user_role = claims.get_role()
            .map_err(|e| JwtError::InvalidToken(e))?;
        
        Ok(user_role.has_permission(&required_role))
    }

    // Get user locale from token (for i18n integration)
    pub fn get_user_locale(&self, token: &str) -> Result<Option<String>, JwtError> {
        let claims = self.validate_token(token)?;
        Ok(claims.locale)
    }
}

// Refresh token claims (simpler than access token)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RefreshTokenClaims {
    pub sub: String,        // User ID
    pub jti: String,        // JWT ID for tracking
    pub exp: usize,         // Expiration time
    pub iat: usize,         // Issued at
    pub iss: String,        // Issuer
    pub token_type: String, // "refresh"
}

impl RefreshTokenClaims {
    pub fn is_expired(&self) -> bool {
        let now = DateUtil::to_timestamp(&DateUtil::now()) as usize;
        now >= self.exp
    }

    pub fn get_user_id(&self) -> Result<Uuid, uuid::Error> {
        Uuid::parse_str(&self.sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::user::dto::UserRole;

    fn create_test_user() -> User {
        crate::shared::models::User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            "hashed_password".to_string(),
            Some("Test User".to_string()),
        )
    }

    fn create_test_jwt_service() -> JwtService {
        let config = JwtConfig {
            secret: "test-secret-key".to_string(),
            algorithm: Algorithm::HS256,
            token_expiry_hours: 1,
            refresh_token_expiry_days: 7,
            issuer: "test-service".to_string(),
        };
        JwtService::new(config)
    }

    #[test]
    fn test_token_generation_and_validation() {
        let jwt_service = create_test_jwt_service();
        let user = create_test_user();

        // Generate token
        let (token, _expires_at) = jwt_service.generate_token(&user).unwrap();
        assert!(!token.is_empty());

        // Validate token
        let claims = jwt_service.validate_token(&token).unwrap();
        assert_eq!(claims.username, user.username);
        assert_eq!(claims.role, user.role.to_string());
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_refresh_token() {
        let jwt_service = create_test_jwt_service();
        let user = create_test_user();

        // Generate refresh token
        let (refresh_token, _expires_at) = jwt_service.generate_refresh_token(&user).unwrap();
        assert!(!refresh_token.is_empty());

        // Validate refresh token
        let refresh_claims = jwt_service.validate_refresh_token(&refresh_token).unwrap();
        assert_eq!(refresh_claims.sub, user.user_id);
        assert_eq!(refresh_claims.token_type, "refresh");
        assert!(!refresh_claims.is_expired());
    }

    #[test]
    fn test_token_extraction_from_header() {
        let jwt_service = create_test_jwt_service();

        // Valid header
        let header = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
        let token = jwt_service.extract_token_from_header(header).unwrap();
        assert_eq!(token, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...");

        // Invalid header
        let invalid_header = "Basic dXNlcjpwYXNz";
        assert!(jwt_service.extract_token_from_header(invalid_header).is_err());

        // Empty token
        let empty_header = "Bearer ";
        assert!(jwt_service.extract_token_from_header(empty_header).is_err());
    }

    #[test]
    fn test_role_permission_check() {
        let jwt_service = create_test_jwt_service();
        let mut user = create_test_user();
        user.set_role(UserRole::Admin);

        let (token, _) = jwt_service.generate_token(&user).unwrap();

        // Admin should have all permissions
        assert!(jwt_service.check_role_permission(&token, UserRole::Admin).unwrap());
        assert!(jwt_service.check_role_permission(&token, UserRole::User).unwrap());
        assert!(jwt_service.check_role_permission(&token, UserRole::Guest).unwrap());
    }

    #[test]
    fn test_user_locale_extraction() {
        let jwt_service = create_test_jwt_service();
        let mut user = create_test_user();
        user.set_locale("vi".to_string());

        let (token, _) = jwt_service.generate_token(&user).unwrap();
        let locale = jwt_service.get_user_locale(&token).unwrap();
        
        assert_eq!(locale, Some("vi".to_string()));
    }
} 