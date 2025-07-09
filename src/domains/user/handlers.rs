pub mod auth_handlers;
pub mod auth_middleware;

pub use auth_handlers::{
    register, login, validate_token, get_profile, logout, refresh_token, auth_health
};
pub use auth_middleware::{
    auth_middleware, require_role, require_admin, require_user, optional_auth_middleware,
    get_claims_from_request, get_user_id_from_request, get_username_from_request, 
    get_user_role_from_request, AuthMiddlewareState
}; 