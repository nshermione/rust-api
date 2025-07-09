use anyhow::{Context, Result};
use mongodb::{Client, Database, options::ClientOptions};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use crate::system::config::{AppConfig, DatabaseConfig};

pub type DatabaseHandle = Arc<Database>;
pub type DatabaseManager = Arc<RwLock<DatabaseService>>;

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub database_name: String,
    pub client: Client,
    pub database: DatabaseHandle,
    pub config: DatabaseConfig,
}

pub struct DatabaseService {
    connections: HashMap<String, ConnectionInfo>,
    default_connection: Option<String>,
}

impl DatabaseService {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            default_connection: None,
        }
    }

    pub async fn initialize(config: &AppConfig) -> Result<DatabaseManager> {
        let mut service = DatabaseService::new();

        info!("🗄️  Initializing database connections...");

        for (index, db_config) in config.databases.iter().enumerate() {
            let connection_name = if index == 0 {
                "default".to_string()
            } else {
                format!("db{}", index)
            };

            let connection_info = Self::create_connection(db_config, &connection_name).await?;

            info!(
                "✅ Connected to database: {} ({})",
                connection_name, db_config.database
            );

            if index == 0 {
                service.default_connection = Some(connection_name.clone());
            }

            service.connections.insert(connection_name, connection_info);
        }

        if service.connections.is_empty() {
            return Err(anyhow::anyhow!("No database connections configured"));
        }

        info!(
            "🚀 Database manager initialized with {} connections",
            service.connections.len()
        );

        Ok(Arc::new(RwLock::new(service)))
    }

    async fn create_connection(
        config: &DatabaseConfig,
        connection_name: &str,
    ) -> Result<ConnectionInfo> {
        // Build connection string
        let connection_string =
            if let (Some(username), Some(password)) = (&config.username, &config.password) {
                format!(
                    "mongodb://{}:{}@{}:{}/{}",
                    username, password, config.host, config.port, config.database
                )
            } else {
                format!(
                    "mongodb://{}:{}/{}",
                    config.host, config.port, config.database
                )
            };

        // Parse connection string and set options
        let mut client_options = ClientOptions::parse(&connection_string)
            .await
            .with_context(|| {
                format!("Failed to parse connection string for {}", connection_name)
            })?;

        // Set connection pool options
        client_options.max_pool_size = Some(config.max_connections);
        client_options.connect_timeout =
            Some(std::time::Duration::from_secs(config.connection_timeout));
        client_options.server_selection_timeout =
            Some(std::time::Duration::from_secs(config.connection_timeout));

        // Create client
        let client = Client::with_options(client_options)
            .with_context(|| format!("Failed to create MongoDB client for {}", connection_name))?;

        // Get database
        let database = client.database(&config.database);

        // Test connection
        database
            .run_command(bson::doc! { "ping": 1 })
            .await
            .with_context(|| format!("Failed to ping database {}", connection_name))?;

        Ok(ConnectionInfo {
            database_name: config.database.clone(),
            client,
            database: Arc::new(database),
            config: config.clone(),
        })
    }

    pub async fn get_database(&self, name: Option<&str>) -> Result<DatabaseHandle> {
        let connection_name = match name {
            Some(name) => name.to_string(),
            None => self
                .default_connection
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("No default database connection"))?
                .clone(),
        };

        self.connections
            .get(&connection_name)
            .map(|conn| conn.database.clone())
            .ok_or_else(|| anyhow::anyhow!("Database connection '{}' not found", connection_name))
    }

    pub async fn get_connection_info(&self, name: Option<&str>) -> Result<ConnectionInfo> {
        let connection_name = match name {
            Some(name) => name.to_string(),
            None => self
                .default_connection
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("No default database connection"))?
                .clone(),
        };

        self.connections
            .get(&connection_name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Database connection '{}' not found", connection_name))
    }

    pub fn list_connections(&self) -> Vec<String> {
        self.connections.keys().cloned().collect()
    }

    pub async fn health_check(&self) -> Result<HashMap<String, bool>> {
        let mut results = HashMap::new();

        for (name, conn) in &self.connections {
            let is_healthy = conn
                .database
                .run_command(bson::doc! { "ping": 1 })
                .await
                .is_ok();

            results.insert(name.clone(), is_healthy);
        }

        Ok(results)
    }

    pub async fn close_connections(&mut self) -> Result<()> {
        info!("🔒 Closing database connections...");

        for (name, _) in self.connections.drain() {
            info!("✅ Closed connection: {}", name);
        }

        self.default_connection = None;

        Ok(())
    }
}

// Helper functions for easy database access
pub async fn get_database(manager: &DatabaseManager, name: Option<&str>) -> Result<DatabaseHandle> {
    let service = manager.read().await;
    service.get_database(name).await
}

pub async fn get_connection_info(
    manager: &DatabaseManager,
    name: Option<&str>,
) -> Result<ConnectionInfo> {
    let service = manager.read().await;
    service.get_connection_info(name).await
}

pub async fn health_check(manager: &DatabaseManager) -> Result<HashMap<String, bool>> {
    let service = manager.read().await;
    service.health_check().await
}
