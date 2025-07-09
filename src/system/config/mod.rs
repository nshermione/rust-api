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
            environment: "development".to_string(),
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let mut config = AppConfig::default();
        
        // Determine environment
        let environment = env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
        config.environment = environment.clone();
        
        // Load environment files in order of priority
        let env_files = vec![
            format!("configs/.env.default"),
            format!("configs/.env.{}", environment),
            format!("configs/.env.local"),
        ];
        
        for env_file in env_files {
            if Path::new(&env_file).exists() {
                load_env_file(&env_file)?;
            }
        }
        
        // Override with environment variables
        config.load_from_env();
        
        Ok(config)
    }
    
    fn load_from_env(&mut self) {
        // Server config
        if let Ok(host) = env::var("SERVER_HOST") {
            self.server.host = host;
        }
        if let Ok(port) = env::var("SERVER_PORT") {
            if let Ok(port) = port.parse::<u16>() {
                self.server.port = port;
            }
        }
        if let Ok(workers) = env::var("SERVER_WORKERS") {
            if let Ok(workers) = workers.parse::<usize>() {
                self.server.workers = workers;
            }
        }
        
        // Log config
        if let Ok(level) = env::var("LOG_LEVEL") {
            self.log.level = level;
        }
        if let Ok(file_path) = env::var("LOG_FILE_PATH") {
            self.log.file_path = Some(file_path);
        }
        
        // Database configs (support multiple databases)
        let mut db_index = 0;
        loop {
            let prefix = if db_index == 0 { "DB".to_string() } else { format!("DB{}", db_index) };
            
            if let Ok(host) = env::var(format!("{}_HOST", prefix)) {
                let db_config = DatabaseConfig {
                    host,
                    port: env::var(format!("{}_PORT", prefix))
                        .ok()
                        .and_then(|p| p.parse().ok())
                        .unwrap_or(27017),
                    database: env::var(format!("{}_DATABASE", prefix))
                        .unwrap_or_else(|_| "default".to_string()),
                    username: env::var(format!("{}_USERNAME", prefix)).ok(),
                    password: env::var(format!("{}_PASSWORD", prefix)).ok(),
                    connection_timeout: env::var(format!("{}_CONNECTION_TIMEOUT", prefix))
                        .ok()
                        .and_then(|t| t.parse().ok())
                        .unwrap_or(10),
                    max_connections: env::var(format!("{}_MAX_CONNECTIONS", prefix))
                        .ok()
                        .and_then(|c| c.parse().ok())
                        .unwrap_or(10),
                };
                
                if db_index < self.databases.len() {
                    self.databases[db_index] = db_config;
                } else {
                    self.databases.push(db_config);
                }
                db_index += 1;
            } else {
                break;
            }
        }
    }
}

fn load_env_file(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        if let Some(pos) = line.find('=') {
            let key = line[..pos].trim();
            let value = line[pos + 1..].trim();
            
            // Remove quotes if present
            let value = if (value.starts_with('"') && value.ends_with('"')) ||
                          (value.starts_with('\'') && value.ends_with('\'')) {
                &value[1..value.len() - 1]
            } else {
                value
            };
            
            unsafe { env::set_var(key, value); }
        }
    }
    
    Ok(())
} 