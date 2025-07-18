use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::Json as JsonResponse,
};
use headers::{Authorization, authorization::Bearer};
use serde_json::json;
use std::sync::Arc;

use crate::{
    domains::user::{
        dto::{
            AuthResponse, AuthErrorResponse, Claims, LoginRequest, RegisterRequest, 
            TokenValidationResponse, UserDto, UserRole
        },
        state::AuthState,
    },
    shared::models::User,
};

use crate::system::config::AppConfig;
use crate::domains::user::services::{JwtService, PasswordService};

// Register a new user
pub async fn register(
    State(state): State<Arc<AuthState>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<JsonResponse<serde_json::Value>, (StatusCode, JsonResponse<AuthErrorResponse>)> {
    // Validate input
    if payload.username.len() < 3 {
        return Err((
            StatusCode::BAD_REQUEST,
            JsonResponse(AuthErrorResponse::new(
                "validation_error",
                "Username must be at least 3 characters long"
            ))
        ));
    }

    if payload.email.is_empty() || !payload.email.contains('@') {
        return Err((
            StatusCode::BAD_REQUEST,
            JsonResponse(AuthErrorResponse::new(
                "validation_error", 
                "Valid email is required"
            ))
        ));
    }

    // TODO: Check if username/email already exists in database
    // For now, we'll simulate a successful registration

    // Hash password
    let password_hash = match state.password_service.hash_password(&payload.password) {
        Ok(hash) => hash,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                JsonResponse(AuthErrorResponse::with_details(
                    "password_error",
                    "Password does not meet requirements",
                    &e.to_string()
                ))
            ));
        }
    };

    // Create user
    let user = User::new(
        payload.username,
        payload.email,
        password_hash,
        payload.full_name,
    );

    // Generate JWT token
    let (token, _expires_at) = match state.jwt_service.generate_token(&user) {
        Ok((token, expires)) => (token, expires),
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                JsonResponse(AuthErrorResponse::new(
                    "token_error",
                    &format!("Failed to generate token: {}", e)
                ))
            ));
        }
    };

    // TODO: Save user to database
    // For now, we'll return success response

    let user_dto: UserDto = (&user).into();
    let auth_response = AuthResponse {
        token,
        token_type: "Bearer".to_string(),
        expires_in: 24 * 60 * 60, // 24 hours in seconds
        user: user_dto,
    };

    Ok(JsonResponse(json!({
        "success": true,
        "message": "User registered successfully",
        "data": auth_response
    })))
}

// Login user
pub async fn login(
    State(state): State<Arc<AuthState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<JsonResponse<serde_json::Value>, (StatusCode, JsonResponse<AuthErrorResponse>)> {
    // Validate input
    if payload.username.is_empty() || payload.password.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            JsonResponse(AuthErrorResponse::new(
                "validation_error",
                "Username and password are required"
            ))
        ));
    }

    // TODO: Find user in database by username or email
    // For now, we'll simulate a user lookup
    let user = User::new(
        payload.username.clone(),
        "user@example.com".to_string(),
        "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK8.".to_string(), // "password123"
        Some("Test User".to_string()),
    );

    // Verify password
    if !state.password_service.verify_password(&payload.password, &user.password_hash)
        .map_err(|e| (
            StatusCode::INTERNAL_SERVER_ERROR,
            JsonResponse(AuthErrorResponse::new("verification_error", &e.to_string()))
        ))? {
        return Err((
            StatusCode::UNAUTHORIZED,
            JsonResponse(AuthErrorResponse::new(
                "auth_error",
                "Invalid username or password"
            ))
        ));
    }

    // Check if user is active
    if !user.is_active {
        return Err((
            StatusCode::FORBIDDEN,
            JsonResponse(AuthErrorResponse::new(
                "account_disabled",
                "Account is disabled"
            ))
        ));
    }

    // Check if account is locked
    if user.is_locked() {
        return Err((
            StatusCode::FORBIDDEN,
            JsonResponse(AuthErrorResponse::new(
                "account_locked",
                "Account is temporarily locked due to too many failed login attempts"
            ))
        ));
    }

    // Update last login
    // TODO: Update user in database
    // user.update_last_login();

    // Generate JWT token
    let (token, _expires_at) = match state.jwt_service.generate_token(&user) {
        Ok((token, expires)) => (token, expires),
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                JsonResponse(AuthErrorResponse::new(
                    "token_error",
                    &format!("Failed to generate token: {}", e)
                ))
            ));
        }
    };

    let user_dto: UserDto = (&user).into();
    let auth_response = AuthResponse {
        token,
        token_type: "Bearer".to_string(),
        expires_in: 24 * 60 * 60, // 24 hours in seconds
        user: user_dto,
    };

    Ok(JsonResponse(json!({
        "success": true,
        "message": "Login successful",
        "data": auth_response
    })))
}

// Validate JWT token
pub async fn validate_token(
    State(state): State<Arc<AuthState>>,
    headers: axum::http::HeaderMap,
) -> Result<JsonResponse<serde_json::Value>, (StatusCode, JsonResponse<AuthErrorResponse>)> {
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            JsonResponse(AuthErrorResponse::new(
                "missing_token",
                "Authorization header is required"
            ))
        ))?;

    let token = state.jwt_service.extract_token_from_header(auth_header)
        .map_err(|e| (
            StatusCode::UNAUTHORIZED,
            JsonResponse(AuthErrorResponse::new("invalid_token", &e.to_string()))
        ))?;
    
    let validation_response = state.jwt_service.get_token_validation_response(&token);
    
    if validation_response.valid {
        Ok(JsonResponse(json!({
            "success": true,
            "message": "Token is valid",
            "data": validation_response
        })))
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            JsonResponse(AuthErrorResponse::new(
                "invalid_token",
                "Token is invalid or expired"
            ))
        ))
    }
}

// Get current user profile
pub async fn get_profile(
    State(state): State<Arc<AuthState>>,
    headers: axum::http::HeaderMap,
) -> Result<JsonResponse<serde_json::Value>, (StatusCode, JsonResponse<AuthErrorResponse>)> {
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            JsonResponse(AuthErrorResponse::new(
                "missing_token",
                "Authorization header is required"
            ))
        ))?;

    let token = state.jwt_service.extract_token_from_header(auth_header)
        .map_err(|e| (
            StatusCode::UNAUTHORIZED,
            JsonResponse(AuthErrorResponse::new("invalid_token", &e.to_string()))
        ))?;
    
    // Validate token and extract claims
    let claims = match state.jwt_service.validate_token(&token) {
        Ok(claims) => claims,
        Err(e) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                JsonResponse(AuthErrorResponse::new(
                    "invalid_token",
                    &format!("Token validation failed: {}", e)
                ))
            ));
        }
    };

    // TODO: Get user from database using claims.sub (user_id)
    // For now, we'll return a mock user profile
    let user = User::new(
        claims.username,
        "user@example.com".to_string(),
        "hashed_password".to_string(),
        Some("Test User".to_string()),
    );

    let user_dto: UserDto = (&user).into();

    Ok(JsonResponse(json!({
        "success": true,
        "message": "Profile retrieved successfully",
        "data": user_dto
    })))
}

// Logout user (invalidate token)
pub async fn logout(
    State(state): State<Arc<AuthState>>,
    headers: axum::http::HeaderMap,
) -> Result<JsonResponse<serde_json::Value>, (StatusCode, JsonResponse<AuthErrorResponse>)> {
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            JsonResponse(AuthErrorResponse::new(
                "missing_token",
                "Authorization header is required"
            ))
        ))?;

    let token = state.jwt_service.extract_token_from_header(auth_header)
        .map_err(|e| (
            StatusCode::UNAUTHORIZED,
            JsonResponse(AuthErrorResponse::new("invalid_token", &e.to_string()))
        ))?;
    
    // Validate token first
    let _claims = match state.jwt_service.validate_token(&token) {
        Ok(claims) => claims,
        Err(e) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                JsonResponse(AuthErrorResponse::new(
                    "invalid_token",
                    &format!("Token validation failed: {}", e)
                ))
            ));
        }
    };

    // TODO: Add token to blacklist or invalidate session in database
    // For now, we'll just return success

    Ok(JsonResponse(json!({
        "success": true,
        "message": "Logout successful"
    })))
}

// Refresh token
pub async fn refresh_token(
    State(state): State<Arc<AuthState>>,
    headers: axum::http::HeaderMap,
) -> Result<JsonResponse<serde_json::Value>, (StatusCode, JsonResponse<AuthErrorResponse>)> {
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            JsonResponse(AuthErrorResponse::new(
                "missing_token",
                "Authorization header is required"
            ))
        ))?;

    let token = state.jwt_service.extract_token_from_header(auth_header)
        .map_err(|e| (
            StatusCode::UNAUTHORIZED,
            JsonResponse(AuthErrorResponse::new("invalid_token", &e.to_string()))
        ))?;
    
    // Validate refresh token
    let refresh_claims = match state.jwt_service.validate_refresh_token(&token) {
        Ok(claims) => claims,
        Err(e) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                JsonResponse(AuthErrorResponse::new(
                    "invalid_refresh_token",
                    &format!("Refresh token validation failed: {}", e)
                ))
            ));
        }
    };

    // TODO: Get user from database using refresh_claims.sub
    // For now, we'll create a mock user
    let user = User::new(
        "testuser".to_string(),
        "user@example.com".to_string(),
        "hashed_password".to_string(),
        Some("Test User".to_string()),
    );

    // Generate new access token
    let (new_token, expires_at) = match state.jwt_service.generate_token(&user) {
        Ok((token, expires)) => (token, expires),
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                JsonResponse(AuthErrorResponse::new(
                    "token_error",
                    &format!("Failed to generate new token: {}", e)
                ))
            ));
        }
    };

    let user_dto: UserDto = (&user).into();
    let auth_response = AuthResponse {
        token: new_token,
        token_type: "Bearer".to_string(),
        expires_in: 24 * 60 * 60, // 24 hours in seconds
        user: user_dto,
    };

    Ok(JsonResponse(json!({
        "success": true,
        "message": "Token refreshed successfully",
        "data": auth_response
    })))
}

// Health check for auth service
pub async fn auth_health() -> JsonResponse<serde_json::Value> {
    JsonResponse(json!({
        "status": "healthy",
        "service": "auth",
        "timestamp": crate::shared::utils::date_util::DateUtil::to_rfc3339(&crate::shared::utils::date_util::DateUtil::now())
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::user::services::{JwtConfig, PasswordConfig};
    use crate::shared::state::SharedState;
    use crate::system::config::AppConfig;
    use crate::domains::user::services::{JwtService, PasswordService};

    fn create_test_auth_state() -> Arc<AuthState> {
        let jwt_config = JwtConfig::default();
        let password_config = PasswordConfig::default();
        
        // Create mock shared state for testing
        let shared_state = Arc::new(SharedState {
            config: Arc::new(AppConfig::default()),
            db_manager: Arc::new(tokio::sync::RwLock::new(crate::system::database::DatabaseService::new())),
            message_loader: Arc::new(crate::system::locale::MessageLoader::new("locales")),
            version_registry: Arc::new(crate::system::versioning::VersionRegistry::new()),
        });
        
        Arc::new(AuthState {
            shared_state,
            jwt_service: JwtService::new(jwt_config),
            password_service: PasswordService::new(password_config),
            config: Arc::new(AppConfig::default()),
        })
    }

    #[tokio::test]
    async fn test_auth_health() {
        let response = auth_health().await;
        let body = response.0;
        
        assert_eq!(body["status"], "healthy");
        assert_eq!(body["service"], "auth");
    }

    #[tokio::test]
    async fn test_register_validation() {
        let state = create_test_auth_state();
        
        // Test short username
        let payload = RegisterRequest {
            username: "ab".to_string(),
            email: "test@example.com".to_string(),
            password: "StrongPassword123!".to_string(),
            full_name: Some("Test User".to_string()),
        };
        
        let result = register(State(state.clone()), Json(payload)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_login_validation() {
        let state = create_test_auth_state();
        
        // Test empty credentials
        let payload = LoginRequest {
            username: "".to_string(),
            password: "".to_string(),
        };
        
        let result = login(State(state.clone()), Json(payload)).await;
        assert!(result.is_err());
    }
} 