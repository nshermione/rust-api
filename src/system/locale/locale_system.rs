use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

// Supported locales - can be extended
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Locale {
    En,    // English (default)
    Vi,    // Vietnamese  
    Ja,    // Japanese
    Ko,    // Korean
    Zh,    // Chinese
}

impl Locale {
    pub fn parse(locale_str: &str) -> Result<Self, LocaleError> {
        match locale_str.to_lowercase().as_str() {
            "en" | "en-us" | "english" => Ok(Locale::En),
            "vi" | "vi-vn" | "vietnamese" => Ok(Locale::Vi),
            "ja" | "ja-jp" | "japanese" => Ok(Locale::Ja),
            "ko" | "ko-kr" | "korean" => Ok(Locale::Ko),
            "zh" | "zh-cn" | "chinese" => Ok(Locale::Zh),
            _ => Err(LocaleError::UnsupportedLocale(locale_str.to_string())),
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            Locale::En => "en".to_string(),
            Locale::Vi => "vi".to_string(),
            Locale::Ja => "ja".to_string(),
            Locale::Ko => "ko".to_string(),
            Locale::Zh => "zh".to_string(),
        }
    }

    pub fn to_full_name(&self) -> &'static str {
        match self {
            Locale::En => "English",
            Locale::Vi => "Tiếng Việt",
            Locale::Ja => "日本語",
            Locale::Ko => "한국어", 
            Locale::Zh => "中文",
        }
    }

    pub fn is_rtl(&self) -> bool {
        // Add RTL locales if needed in future
        false
    }
}

impl Default for Locale {
    fn default() -> Self {
        Locale::En
    }
}

impl std::fmt::Display for Locale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[derive(Debug, Clone)]
pub enum LocaleSource {
    Header,      // Accept-Language header
    Token,       // From JWT token
    Query,       // URL query parameter
    Default,     // Fallback
}

#[derive(Debug, Clone)]
pub struct LocaleInfo {
    pub locale: Locale,
    pub source: LocaleSource,
    pub fallback: Option<Locale>,
}

impl Default for LocaleInfo {
    fn default() -> Self {
        Self {
            locale: Locale::default(),
            source: LocaleSource::Default,
            fallback: Some(Locale::En),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LocaleError {
    #[error("Unsupported locale: {0}")]
    UnsupportedLocale(String),
    #[error("Locale extraction failed: {0}")]
    ExtractionFailed(String),
    #[error("Message not found: {0}")]
    MessageNotFound(String),
    #[error("Translation failed: {0}")]
    TranslationFailed(String),
    #[error("Locale file error: {0}")]
    FileError(String),
}

impl IntoResponse for LocaleError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            LocaleError::UnsupportedLocale(msg) => (
                StatusCode::BAD_REQUEST,
                format!("Unsupported locale: {}", msg)
            ),
            LocaleError::ExtractionFailed(msg) => (
                StatusCode::BAD_REQUEST,
                format!("Locale extraction failed: {}", msg)
            ),
            LocaleError::MessageNotFound(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Message not found: {}", msg)
            ),
            LocaleError::TranslationFailed(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Translation failed: {}", msg)
            ),
            LocaleError::FileError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Locale file error: {}", msg)
            ),
        };

        let body = Json(serde_json::json!({
            "error": "LOCALE_ERROR",
            "message": error_message,
            "timestamp": crate::shared::utils::date_util::DateUtil::to_rfc3339(&crate::shared::utils::date_util::DateUtil::now())
        }));

        (status, body).into_response()
    }
}

#[derive(Debug, Clone)]
pub struct LocaleRegistry {
    supported_locales: Vec<Locale>,
    default_locale: Locale,
    fallback_chain: HashMap<Locale, Vec<Locale>>,
}

impl LocaleRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            supported_locales: vec![
                Locale::En,
                Locale::Vi,
                // Add more as needed
            ],
            default_locale: Locale::En,
            fallback_chain: HashMap::new(),
        };

        // Setup fallback chains
        registry.setup_fallback_chains();
        registry
    }

    fn setup_fallback_chains(&mut self) {
        // Vietnamese fallback to English
        self.fallback_chain.insert(
            Locale::Vi,
            vec![Locale::En]
        );
        
        // Japanese fallback to English
        self.fallback_chain.insert(
            Locale::Ja,
            vec![Locale::En]
        );
        
        // Korean fallback to English  
        self.fallback_chain.insert(
            Locale::Ko,
            vec![Locale::En]
        );
        
        // Chinese fallback to English
        self.fallback_chain.insert(
            Locale::Zh,
            vec![Locale::En]
        );
        
        // English has no fallback (it's the base)
    }

    pub fn is_supported(&self, locale: &Locale) -> bool {
        self.supported_locales.contains(locale)
    }

    pub fn get_supported_locales(&self) -> &Vec<Locale> {
        &self.supported_locales
    }

    pub fn get_default_locale(&self) -> &Locale {
        &self.default_locale
    }

    pub fn get_fallback_chain(&self, locale: &Locale) -> Vec<Locale> {
        self.fallback_chain
            .get(locale)
            .cloned()
            .unwrap_or_else(|| vec![self.default_locale.clone()])
    }

    pub fn resolve_locale(&self, requested: &Locale) -> LocaleInfo {
        if self.is_supported(requested) {
            LocaleInfo {
                locale: requested.clone(),
                source: LocaleSource::Default, // Will be set by extractor
                fallback: self.fallback_chain.get(requested).and_then(|chain| chain.first().cloned()),
            }
        } else {
            // Fallback to default
            LocaleInfo {
                locale: self.default_locale.clone(),
                source: LocaleSource::Default,
                fallback: None,
            }
        }
    }

    pub fn add_locale(&mut self, locale: Locale, fallback_chain: Option<Vec<Locale>>) {
        if !self.supported_locales.contains(&locale) {
            self.supported_locales.push(locale.clone());
        }
        
        if let Some(chain) = fallback_chain {
            self.fallback_chain.insert(locale, chain);
        }
    }
}

impl Default for LocaleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locale_parsing() {
        assert_eq!(Locale::parse("en").unwrap(), Locale::En);
        assert_eq!(Locale::parse("vi").unwrap(), Locale::Vi);
        assert_eq!(Locale::parse("EN").unwrap(), Locale::En);
        assert_eq!(Locale::parse("en-US").unwrap(), Locale::En);
        assert!(Locale::parse("invalid").is_err());
    }

    #[test]
    fn test_locale_display() {
        assert_eq!(Locale::En.to_string(), "en");
        assert_eq!(Locale::Vi.to_string(), "vi");
        assert_eq!(Locale::En.to_full_name(), "English");
        assert_eq!(Locale::Vi.to_full_name(), "Tiếng Việt");
    }

    #[test]
    fn test_locale_registry() {
        let registry = LocaleRegistry::new();
        
        assert!(registry.is_supported(&Locale::En));
        assert!(registry.is_supported(&Locale::Vi));
        assert_eq!(registry.get_default_locale(), &Locale::En);
        
        let fallback = registry.get_fallback_chain(&Locale::Vi);
        assert_eq!(fallback, vec![Locale::En]);
    }

    #[test]
    fn test_locale_resolution() {
        let registry = LocaleRegistry::new();
        
        let info = registry.resolve_locale(&Locale::Vi);
        assert_eq!(info.locale, Locale::Vi);
        assert_eq!(info.fallback, Some(Locale::En));
    }
} 