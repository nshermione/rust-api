use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{Locale, LocaleError, LocaleRegistry};

// Message data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Messages {
    pub messages: HashMap<String, String>,
    pub metadata: Option<MessageMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageMetadata {
    pub locale: String,
    pub version: String,
    pub last_updated: String,
    pub translators: Option<Vec<String>>,
}

impl Messages {
    pub fn new() -> Self {
        Self {
            messages: HashMap::new(),
            metadata: None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.messages.get(key)
    }

    pub fn get_with_fallback(&self, key: &str, fallback_messages: &[&Messages]) -> Option<String> {
        // Try current messages first
        if let Some(message) = self.get(key) {
            return Some(message.clone());
        }

        // Try fallback messages
        for fallback in fallback_messages {
            if let Some(message) = fallback.get(key) {
                return Some(message.clone());
            }
        }

        None
    }

    pub fn insert(&mut self, key: String, message: String) {
        self.messages.insert(key, message);
    }

    pub fn merge(&mut self, other: Messages) {
        self.messages.extend(other.messages);
        if self.metadata.is_none() {
            self.metadata = other.metadata;
        }
    }
}

impl Default for Messages {
    fn default() -> Self {
        Self::new()
    }
}

// Message loader with caching
#[derive(Debug)]
pub struct MessageLoader {
    base_path: PathBuf,
    cache: Arc<RwLock<HashMap<Locale, Messages>>>,
    registry: LocaleRegistry,
}

impl MessageLoader {
    pub fn new<P: AsRef<Path>>(base_path: P) -> Self {
        Self {
            base_path: base_path.as_ref().to_path_buf(),
            cache: Arc::new(RwLock::new(HashMap::new())),
            registry: LocaleRegistry::new(),
        }
    }

    // Load messages for a specific locale
    pub async fn load_locale(&self, locale: &Locale) -> Result<Messages, LocaleError> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(messages) = cache.get(locale) {
                return Ok(messages.clone());
            }
        }

        // Load from file
        let messages = self.load_from_file(locale).await?;

        // Cache the result
        {
            let mut cache = self.cache.write().await;
            cache.insert(locale.clone(), messages.clone());
        }

        Ok(messages)
    }

    // Load messages from JSON file
    async fn load_from_file(&self, locale: &Locale) -> Result<Messages, LocaleError> {
        let file_path = self.get_locale_file_path(locale);
        
        if !file_path.exists() {
            return Err(LocaleError::FileError(format!(
                "Locale file not found: {:?}",
                file_path
            )));
        }

        let content = tokio::fs::read_to_string(&file_path)
            .await
            .map_err(|e| LocaleError::FileError(format!(
                "Failed to read locale file {:?}: {}",
                file_path, e
            )))?;

        let messages: Messages = serde_json::from_str(&content)
            .map_err(|e| LocaleError::FileError(format!(
                "Failed to parse locale file {:?}: {}",
                file_path, e
            )))?;

        Ok(messages)
    }

    fn get_locale_file_path(&self, locale: &Locale) -> PathBuf {
        self.base_path.join(format!("{}.json", locale.to_string()))
    }

    // Get message with fallback chain
    pub async fn get_message(&self, key: &str, locale: &Locale) -> Result<String, LocaleError> {
        // Load primary locale messages
        let messages = self.load_locale(locale).await?;
        
        // Try to get message from primary locale
        if let Some(message) = messages.get(key) {
            return Ok(message.clone());
        }

        // Try fallback chain
        let fallback_chain = self.registry.get_fallback_chain(locale);
        for fallback_locale in &fallback_chain {
            if let Ok(fallback_messages) = self.load_locale(fallback_locale).await {
                if let Some(message) = fallback_messages.get(key) {
                    return Ok(message.clone());
                }
            }
        }

        Err(LocaleError::MessageNotFound(format!(
            "Message '{}' not found for locale '{}' or its fallbacks",
            key, locale
        )))
    }

    // Get message with parameters
    pub async fn get_message_with_params(
        &self,
        key: &str,
        locale: &Locale,
        params: &HashMap<String, String>,
    ) -> Result<String, LocaleError> {
        let template = self.get_message(key, locale).await?;
        Ok(interpolate_message(&template, params))
    }

    // Preload all supported locales
    pub async fn preload_all(&self) -> Result<(), LocaleError> {
        let supported_locales = self.registry.get_supported_locales();
        
        for locale in supported_locales {
            if let Err(e) = self.load_locale(locale).await {
                eprintln!("Warning: Failed to preload locale {}: {}", locale, e);
            }
        }

        Ok(())
    }

    // Clear cache
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    // Reload a specific locale
    pub async fn reload_locale(&self, locale: &Locale) -> Result<(), LocaleError> {
        {
            let mut cache = self.cache.write().await;
            cache.remove(locale);
        }
        
        self.load_locale(locale).await?;
        Ok(())
    }

    // Get available locales based on files
    pub async fn get_available_locales(&self) -> Result<Vec<Locale>, LocaleError> {
        let mut available_locales = Vec::new();

        if !self.base_path.exists() {
            return Ok(available_locales);
        }

        let mut entries = tokio::fs::read_dir(&self.base_path)
            .await
            .map_err(|e| LocaleError::FileError(format!(
                "Failed to read locale directory: {}", e
            )))?;

        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            LocaleError::FileError(format!("Failed to read directory entry: {}", e))
        })? {
            let path = entry.path();
            if path.is_file() {
                if let Some(extension) = path.extension() {
                    if extension == "json" {
                        if let Some(file_stem) = path.file_stem() {
                            if let Some(locale_str) = file_stem.to_str() {
                                if let Ok(locale) = Locale::parse(locale_str) {
                                    available_locales.push(locale);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(available_locales)
    }
}

// Simple message interpolation
fn interpolate_message(template: &str, params: &HashMap<String, String>) -> String {
    let mut result = template.to_string();
    
    for (key, value) in params {
        let placeholder = format!("{{{}}}", key);
        result = result.replace(&placeholder, value);
    }
    
    result
}

// Helper functions for common translations
pub async fn t(loader: &MessageLoader, key: &str, locale: &Locale) -> String {
    loader.get_message(key, locale).await.unwrap_or_else(|_| {
        format!("[{}]", key) // Show missing key in brackets
    })
}

pub async fn t_with_params(
    loader: &MessageLoader,
    key: &str,
    locale: &Locale,
    params: HashMap<String, String>,
) -> String {
    loader.get_message_with_params(key, locale, &params).await.unwrap_or_else(|_| {
        format!("[{}]", key)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    async fn create_test_locale_files(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
        // English messages
        let en_messages = Messages {
            messages: [
                ("hello".to_string(), "Hello".to_string()),
                ("goodbye".to_string(), "Goodbye".to_string()),
                ("welcome".to_string(), "Welcome, {name}!".to_string()),
            ].into_iter().collect(),
            metadata: Some(MessageMetadata {
                locale: "en".to_string(),
                version: "1.0".to_string(),
                last_updated: "2024-01-01".to_string(),
                translators: None,
            }),
        };

        // Vietnamese messages (partial)
        let vi_messages = Messages {
            messages: [
                ("hello".to_string(), "Xin chào".to_string()),
                ("welcome".to_string(), "Chào mừng, {name}!".to_string()),
            ].into_iter().collect(),
            metadata: Some(MessageMetadata {
                locale: "vi".to_string(),
                version: "1.0".to_string(),
                last_updated: "2024-01-01".to_string(),
                translators: Some(vec!["Translator 1".to_string()]),
            }),
        };

        fs::write(
            dir.join("en.json"),
            serde_json::to_string_pretty(&en_messages)?,
        )?;

        fs::write(
            dir.join("vi.json"),
            serde_json::to_string_pretty(&vi_messages)?,
        )?;

        Ok(())
    }

    #[tokio::test]
    async fn test_message_loading() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        create_test_locale_files(temp_dir.path()).await?;

        let loader = MessageLoader::new(temp_dir.path());

        // Test loading English messages
        let en_messages = loader.load_locale(&Locale::En).await?;
        assert_eq!(en_messages.get("hello"), Some(&"Hello".to_string()));

        // Test loading Vietnamese messages
        let vi_messages = loader.load_locale(&Locale::Vi).await?;
        assert_eq!(vi_messages.get("hello"), Some(&"Xin chào".to_string()));

        Ok(())
    }

    #[tokio::test]
    async fn test_message_fallback() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        create_test_locale_files(temp_dir.path()).await?;

        let loader = MessageLoader::new(temp_dir.path());

        // Test getting message that exists in Vietnamese
        let hello_vi = loader.get_message("hello", &Locale::Vi).await?;
        assert_eq!(hello_vi, "Xin chào");

        // Test getting message that doesn't exist in Vietnamese but exists in English (fallback)
        let goodbye_vi = loader.get_message("goodbye", &Locale::Vi).await?;
        assert_eq!(goodbye_vi, "Goodbye");

        Ok(())
    }

    #[tokio::test]
    async fn test_message_interpolation() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        create_test_locale_files(temp_dir.path()).await?;

        let loader = MessageLoader::new(temp_dir.path());

        let mut params = HashMap::new();
        params.insert("name".to_string(), "John".to_string());

        let welcome_en = loader.get_message_with_params("welcome", &Locale::En, &params).await?;
        assert_eq!(welcome_en, "Welcome, John!");

        let welcome_vi = loader.get_message_with_params("welcome", &Locale::Vi, &params).await?;
        assert_eq!(welcome_vi, "Chào mừng, John!");

        Ok(())
    }

    #[tokio::test]
    async fn test_available_locales() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        create_test_locale_files(temp_dir.path()).await?;

        let loader = MessageLoader::new(temp_dir.path());
        let available = loader.get_available_locales().await?;

        assert!(available.contains(&Locale::En));
        assert!(available.contains(&Locale::Vi));

        Ok(())
    }

    #[test]
    fn test_interpolate_message() {
        let template = "Hello, {name}! You have {count} messages.";
        let mut params = HashMap::new();
        params.insert("name".to_string(), "Alice".to_string());
        params.insert("count".to_string(), "5".to_string());

        let result = interpolate_message(template, &params);
        assert_eq!(result, "Hello, Alice! You have 5 messages.");
    }

    #[tokio::test]
    async fn test_real_locale_files() -> Result<(), Box<dyn std::error::Error>> {
        let locales_path = std::path::Path::new("locales");
        
        if !locales_path.exists() {
            // Skip test if locales directory doesn't exist
            return Ok(());
        }

        let loader = MessageLoader::new(locales_path);

        // Test loading English messages
        if let Ok(en_messages) = loader.load_locale(&Locale::En).await {
            assert!(en_messages.get("hello").is_some());
            assert_eq!(en_messages.get("hello").unwrap(), "Hello");
            println!("✅ English messages loaded successfully");
        }

        // Test loading Vietnamese messages
        if let Ok(vi_messages) = loader.load_locale(&Locale::Vi).await {
            assert!(vi_messages.get("hello").is_some());
            assert_eq!(vi_messages.get("hello").unwrap(), "Xin chào");
            println!("✅ Vietnamese messages loaded successfully");
        }

        // Test message with parameters
        let mut params = HashMap::new();
        params.insert("name".to_string(), "Sếp".to_string());
        
        if let Ok(welcome_vi) = loader.get_message_with_params("welcome", &Locale::Vi, &params).await {
            assert_eq!(welcome_vi, "Chào mừng, Sếp!");
            println!("✅ Vietnamese parameterized message: {}", welcome_vi);
        }

        // Test fallback (message that doesn't exist in Vietnamese)
        if let Ok(goodbye_vi) = loader.get_message("goodbye", &Locale::Vi).await {
            // Should fallback to English if Vietnamese doesn't have this message
            println!("✅ Fallback message: {}", goodbye_vi);
        }

        Ok(())
    }
} 