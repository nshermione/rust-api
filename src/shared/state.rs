use std::sync::Arc;
use crate::system::config::AppConfig;
use crate::system::database::DatabaseService;
use crate::system::locale::MessageLoader;
use crate::system::versioning::VersionRegistry;

/// Global shared state containing system-level dependencies
/// This state is shared across all domains and contains core infrastructure
#[derive(Clone)]
pub struct SharedState {
    pub config: Arc<AppConfig>,
    pub db_manager: Arc<tokio::sync::RwLock<DatabaseService>>,
    pub message_loader: Arc<MessageLoader>,
    pub version_registry: Arc<VersionRegistry>,
} 