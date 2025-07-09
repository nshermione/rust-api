use std::sync::Arc;
use crate::shared::state::SharedState;
use crate::domains::user::services::{JwtService, PasswordService};
use crate::system::config::AppConfig;

/// Auth-specific state containing authentication services
/// This state is specific to the auth domain
pub struct AuthState {
    pub shared_state: Arc<SharedState>,
    pub jwt_service: JwtService,
    pub password_service: PasswordService,
    pub config: Arc<AppConfig>,
} 