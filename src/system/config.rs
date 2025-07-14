use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub connection_timeout: u64,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    pub level: String,
    pub file_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub log: LogConfig,
    pub databases: Vec<DatabaseConfig>,
    pub environment: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 3001,
                workers: 4,
            },
            log: LogConfig {
                level: "info".to_string(),
                file_path: None,
            },
            databases: vec![],
            environment: "default".to_string(),
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        // Determine environment from APP_ENV or default to "default"
        let environment = env::var("APP_ENV").unwrap_or_else(|_| "default".to_string());

        // Try to load environment-specific config first
        let config_file = format!("configs/config.{}.json", environment);
        if Path::new(&config_file).exists() {
            let content = fs::read_to_string(&config_file)?;
            let mut config: AppConfig = serde_json::from_str(&content)?;

            // Ensure environment field matches actual environment
            config.environment = environment;

            return Ok(config);
        }

        // Fallback to default config
        let default_config_file = "configs/config.default.json";
        if Path::new(default_config_file).exists() {
            let content = fs::read_to_string(default_config_file)?;
            let mut config: AppConfig = serde_json::from_str(&content)?;

            // Set environment to actual environment even when using default config
            config.environment = environment;

            return Ok(config);
        }

        // If no config files found, return default config
        let mut config = AppConfig::default();
        config.environment = environment;

        Ok(config)
    }
} 