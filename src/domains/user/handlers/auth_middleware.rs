use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use headers::{Authorization, authorization::Bearer};
use serde_json::json;
use std::sync::Arc;

use crate::{
    domains::user::{
        dto::{AuthErrorResponse, UserRole},
        services::JwtService,
    },
    system::config::AppConfig,
};

// Shared state for auth middleware
pub struct AuthMiddlewareState {
    pub jwt_service: JwtService,
    pub config: Arc<AppConfig>,
}

// Authentication middleware that validates JWT tokens
pub async fn auth_middleware(
    State(state): State<Arc<AuthMiddlewareState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<AuthErrorResponse>)> {
    // Extract Authorization header
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            Json(AuthErrorResponse::new(
                "missing_token",
                "Authorization header is required"
            ))
        ))?;

    // Extract token from Bearer header
    let token = state.jwt_service.extract_token_from_header(auth_header)
        .map_err(|e| (
            StatusCode::UNAUTHORIZED,
            Json(AuthErrorResponse::new("invalid_token", &e.to_string()))
        ))?;

    // Validate token
    let claims = state.jwt_service.validate_token(&token)
        .map_err(|e| (
            StatusCode::UNAUTHORIZED,
            Json(AuthErrorResponse::new("invalid_token", &e.to_string()))
        ))?;

    // Check if token is expired
    if claims.is_expired() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(AuthErrorResponse::new(
                "token_expired",
                "Token has expired"
            ))
        ));
    }

    // Add claims to request extensions for use in handlers
    let mut request = request;
    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

// Role-based authorization middleware
pub async fn require_role(
    required_role: UserRole,
    State(state): State<Arc<AuthMiddlewareState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<AuthErrorResponse>)> {
    // Extract Authorization header
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            Json(AuthErrorResponse::new(
                "missing_token",
                "Authorization header is required"
            ))
        ))?;

    // Extract token from Bearer header
    let token = state.jwt_service.extract_token_from_header(auth_header)
        .map_err(|e| (
            StatusCode::UNAUTHORIZED,
            Json(AuthErrorResponse::new("invalid_token", &e.to_string()))
        ))?;

    // Check role permission
    let has_permission = state.jwt_service.check_role_permission(&token, required_role)
        .map_err(|e| (
            StatusCode::UNAUTHORIZED,
            Json(AuthErrorResponse::new("invalid_token", &e.to_string()))
        ))?;

    if !has_permission {
        return Err((
            StatusCode::FORBIDDEN,
            Json(AuthErrorResponse::new(
                "insufficient_permissions",
                "You don't have permission to access this resource"
            ))
        ));
    }

    // Validate token and add claims to request
    let claims = state.jwt_service.validate_token(&token)
        .map_err(|e| (
            StatusCode::UNAUTHORIZED,
            Json(AuthErrorResponse::new("invalid_token", &e.to_string()))
        ))?;

    let mut request = request;
    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

// Admin-only middleware
pub async fn require_admin(
    State(state): State<Arc<AuthMiddlewareState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<AuthErrorResponse>)> {
    require_role(UserRole::Admin, State(state), headers, request, next).await
}

// User or higher middleware
pub async fn require_user(
    State(state): State<Arc<AuthMiddlewareState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<AuthErrorResponse>)> {
    require_role(UserRole::User, State(state), headers, request, next).await
}

// Optional authentication middleware (doesn't fail if no token)
pub async fn optional_auth_middleware(
    State(state): State<Arc<AuthMiddlewareState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<AuthErrorResponse>)> {
    // Try to extract Authorization header
    if let Some(auth_header) = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
    {
        // Try to extract and validate token
        if let Ok(token) = state.jwt_service.extract_token_from_header(auth_header) {
            if let Ok(claims) = state.jwt_service.validate_token(&token) {
                // Add claims to request extensions if token is valid
                let mut request = request;
                request.extensions_mut().insert(claims);
                return Ok(next.run(request).await);
            }
        }
    }

    // Continue without authentication if no valid token
    Ok(next.run(request).await)
}

// Helper function to extract claims from request extensions
pub fn get_claims_from_request(request: &Request) -> Option<crate::domains::user::dto::Claims> {
    request.extensions().get::<crate::domains::user::dto::Claims>().cloned()
}

// Helper function to get user ID from request
pub fn get_user_id_from_request(request: &Request) -> Option<String> {
    request
        .extensions()
        .get::<crate::domains::user::dto::Claims>()
        .map(|claims| claims.sub.clone())
}

// Helper function to get username from request
pub fn get_username_from_request(request: &Request) -> Option<String> {
    request
        .extensions()
        .get::<crate::domains::user::dto::Claims>()
        .map(|claims| claims.username.clone())
}

// Helper function to get user role from request
pub fn get_user_role_from_request(request: &Request) -> Option<UserRole> {
    request
        .extensions()
        .get::<crate::domains::user::dto::Claims>()
        .and_then(|claims| claims.get_role().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::user::services::JwtConfig;
    use axum::http::Request;

    fn create_test_auth_state() -> Arc<AuthMiddlewareState> {
        Arc::new(AuthMiddlewareState {
            jwt_service: JwtService::new(JwtConfig::default()),
            config: Arc::new(AppConfig::default()),
        })
    }

    #[tokio::test]
    #[ignore]
    async fn test_auth_middleware_missing_token() {
        // This test is ignored due to restriction in constructing axum::middleware::Next in axum 0.8.
        // The middleware logic is covered in integration tests.
    }

    #[test]
    fn test_get_claims_from_request() {
        let mut request = Request::new(axum::body::Body::empty());
        let claims = crate::domains::user::dto::Claims::new(
            uuid::Uuid::new_v4(),
            "testuser".to_string(),
            UserRole::User,
            Some("en".to_string()),
            24
        );
        request.extensions_mut().insert(claims.clone());
        
        let extracted_claims = get_claims_from_request(&request);
        assert!(extracted_claims.is_some());
        assert_eq!(extracted_claims.unwrap().username, "testuser");
    }
} 