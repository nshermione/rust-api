use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::{debug, error, info, warn};

mod domains;
mod middleware;
mod shared;
mod system;

use axum::extract::State;
use domains::user::{
    handlers::{auth_health, login, logout, register, validate_token},
    services::{JwtConfig, PasswordConfig},
    state::AuthState,
};
use shared::state::SharedState;
const API_VERSION: &str = "1.0";
use system::{
    config::AppConfig,
    database::{DatabaseService, health_check},
    locale::MessageLoader,
    versioning::VersionRegistry,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration first
    let config = AppConfig::load()?;

    // Initialize logging with level from config
    tracing_subscriber::fmt()
        .with_env_filter(&config.log.level)
        .with_target(false)
        .with_thread_ids(true)
        .with_thread_names(true)
        .init();

    info!("=== AXUM API SERVICE ===");

    // Load configuration
    info!("✅ Configuration loaded successfully");
    info!("🌍 Environment: {}", config.environment);
    info!("📊 Log Level: {}", config.log.level);

    // Initialize database
    info!("🗄️  Initializing database connections...");
    let db_manager = system::database::DatabaseService::initialize(&config).await?;
    info!("🚀 Database manager initialized successfully");

    // Initialize locale system
    let message_loader = Arc::new(MessageLoader::new("locales"));

    // Initialize versioning system
    let mut version_registry = VersionRegistry::new();
    version_registry.register_version(
        system::versioning::versioning_system::ApiVersion::new(1, 0),
        true,
    );
    version_registry.register_version(
        system::versioning::versioning_system::ApiVersion::new(2, 0),
        true,
    );
    let version_registry = Arc::new(version_registry);

    // Initialize shared state first
    let shared_state = Arc::new(SharedState {
        config: Arc::new(config.clone()),
        db_manager,
        message_loader,
        version_registry,
    });

    // Initialize auth services
    let jwt_config = JwtConfig {
        secret: "your-secret-key".to_string(), // TODO: Load from config
        algorithm: jsonwebtoken::Algorithm::HS256,
        token_expiry_hours: 24,
        refresh_token_expiry_days: 30,
        issuer: "rust-api-service".to_string(),
    };

    let password_config = PasswordConfig {
        min_length: 8,
        require_uppercase: true,
        require_lowercase: true,
        require_numbers: true,
        require_special_chars: true,
        bcrypt_cost: 12,
    };

    // Initialize auth state with reference to shared state
    let auth_state = Arc::new(AuthState {
        shared_state: Arc::clone(&shared_state),
        jwt_service: domains::user::services::JwtService::new(jwt_config),
        password_service: domains::user::services::PasswordService::new(password_config),
        config: Arc::new(config.clone()),
    });

    // Router will use auth_state for auth endpoints

    // Build router
    let app = Router::new()
        // Health and info endpoints (use shared_state)
        .route("/health", get(health_handler))
        .route("/config", get(config_handler))
        // Auth endpoints (use auth_state)
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/validate", get(validate_token))
        .route("/auth/logout", post(logout))
        .route("/auth/health", get(auth_health))
        .with_state(auth_state)
        .layer(CorsLayer::permissive());

    // Start server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    info!("🚀 Server running on http://{}", addr);
    info!("📖 Try: http://{}/config", addr);
    info!("🔐 Auth endpoints: /auth/register, /auth/login, /auth/validate");
    info!("🏷️  Current API version: {}", API_VERSION);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// Health check handler
async fn health_handler(
    State(state): State<Arc<AuthState>>,
) -> axum::response::Json<serde_json::Value> {
    info!("Health check requested");
    axum::response::Json(serde_json::json!({
        "status": "healthy",
        "timestamp": crate::shared::utils::date_util::DateUtil::to_rfc3339(&crate::shared::utils::date_util::DateUtil::now()),
        "environment": state.shared_state.config.environment,
        "api_version": API_VERSION
    }))
}

// Config handler
async fn config_handler(
    State(state): State<Arc<AuthState>>,
) -> axum::response::Json<serde_json::Value> {
    info!("Config info requested");
    axum::response::Json(serde_json::json!({
        "environment": state.shared_state.config.environment,
        "server": {
            "host": state.shared_state.config.server.host,
            "port": state.shared_state.config.server.port
        },
        "databases": state.shared_state.config.databases.len(),
        "api_version": API_VERSION
    }))
}
