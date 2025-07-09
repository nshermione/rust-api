use axum::{
    extract::Request,
    http::HeaderMap,
};
use serde::Deserialize;

use super::{Locale, LocaleInfo, LocaleSource, LocaleError, LocaleRegistry};

// Query parameters for locale extraction
#[derive(Debug, Deserialize)]
pub struct LocaleQuery {
    pub lang: Option<String>,
    pub locale: Option<String>,
}

// Helper function to extract LocaleInfo from request
pub fn extract_locale_info_from_request(request: &Request) -> Option<LocaleInfo> {
    request.extensions().get::<LocaleInfo>().cloned()
}

// Extract locale from Accept-Language header
pub fn extract_locale_from_headers(headers: &HeaderMap) -> Option<String> {
    // Check for custom locale header first
    if let Some(locale_header) = headers.get("accept-locale") {
        if let Ok(locale_str) = locale_header.to_str() {
            return Some(locale_str.to_string());
        }
    }

    // Parse Accept-Language header
    if let Some(accept_language) = headers.get("accept-language") {
        if let Ok(accept_str) = accept_language.to_str() {
            return parse_accept_language(accept_str);
        }
    }

    None
}

// Parse Accept-Language header to extract preferred locale
pub fn parse_accept_language(accept_language: &str) -> Option<String> {
    // Parse "en-US,en;q=0.9,vi;q=0.8" format
    let mut locales: Vec<(String, f32)> = Vec::new();

    for part in accept_language.split(',') {
        let part = part.trim();
        if let Some((locale, quality)) = parse_locale_with_quality(part) {
            locales.push((locale, quality));
        }
    }

    // Sort by quality (highest first)
    locales.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Return the highest quality locale
    locales.first().map(|(locale, _)| locale.clone())
}

fn parse_locale_with_quality(part: &str) -> Option<(String, f32)> {
    if let Some((locale, quality_str)) = part.split_once(";q=") {
        let quality = quality_str.parse::<f32>().unwrap_or(1.0);
        let locale = normalize_locale(locale.trim());
        Some((locale, quality))
    } else {
        let locale = normalize_locale(part.trim());
        Some((locale, 1.0))
    }
}

fn normalize_locale(locale: &str) -> String {
    // Convert "en-US" to "en", "vi-VN" to "vi", etc.
    if let Some((lang, _)) = locale.split_once('-') {
        lang.to_lowercase()
    } else {
        locale.to_lowercase()
    }
}

// Extract locale from JWT token payload
pub fn extract_locale_from_token(token: &str) -> Result<Option<String>, LocaleError> {
    // This is a simplified implementation
    // In a real app, you'd decode the JWT properly
    if token.contains("locale") {
        // Mock extraction - in reality use a JWT library
        if token.contains("vi") {
            Ok(Some("vi".to_string()))
        } else if token.contains("en") {
            Ok(Some("en".to_string()))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

// Extract locale from query parameters
pub fn extract_locale_from_query(query: &LocaleQuery) -> Option<String> {
    query.locale.clone().or_else(|| query.lang.clone())
}

// Main locale extraction function with priority
pub async fn extract_locale_info(
    headers: &HeaderMap,
    query: Option<&LocaleQuery>,
) -> Result<LocaleInfo, LocaleError> {
    let registry = LocaleRegistry::new();

    // Priority 1: Query parameter
    if let Some(query) = query {
        if let Some(locale_str) = extract_locale_from_query(query) {
            if let Ok(locale) = Locale::parse(&locale_str) {
                let mut info = registry.resolve_locale(&locale);
                info.source = LocaleSource::Query;
                return Ok(info);
            }
        }
    }

    // Priority 2: Accept-Language header
    if let Some(locale_str) = extract_locale_from_headers(headers) {
        if let Ok(locale) = Locale::parse(&locale_str) {
            let mut info = registry.resolve_locale(&locale);
            info.source = LocaleSource::Header;
            return Ok(info);
        }
    }

    // Priority 3: Check Authorization header for token
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = extract_bearer_token(auth_str) {
                if let Ok(Some(locale_str)) = extract_locale_from_token(token) {
                    if let Ok(locale) = Locale::parse(&locale_str) {
                        let mut info = registry.resolve_locale(&locale);
                        info.source = LocaleSource::Token;
                        return Ok(info);
                    }
                }
            }
        }
    }

    // Priority 4: Default locale
    let mut info = registry.resolve_locale(&Locale::default());
    info.source = LocaleSource::Default;
    Ok(info)
}

fn extract_bearer_token(auth_header: &str) -> Option<&str> {
    if auth_header.starts_with("Bearer ") {
        Some(&auth_header[7..])
    } else {
        None
    }
}

// Extractor for just the Locale
#[derive(Debug, Clone)]
pub struct LocaleExtractor(pub Locale);

impl LocaleExtractor {
    pub fn inner(self) -> Locale {
        self.0
    }

    pub fn from_request(request: &Request) -> Option<Self> {
        extract_locale_info_from_request(request).map(|info| LocaleExtractor(info.locale))
    }
}

impl std::ops::Deref for LocaleExtractor {
    type Target = Locale;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Helper trait for locale-aware handlers
pub trait LocaleAware {
    fn get_locale(&self) -> &Locale;
    fn get_locale_source(&self) -> &LocaleSource;
    fn is_locale(&self, locale: &Locale) -> bool {
        self.get_locale() == locale
    }
    fn is_english(&self) -> bool {
        self.is_locale(&Locale::En)
    }
    fn is_vietnamese(&self) -> bool {
        self.is_locale(&Locale::Vi)
    }
}

impl LocaleAware for LocaleInfo {
    fn get_locale(&self) -> &Locale {
        &self.locale
    }

    fn get_locale_source(&self) -> &LocaleSource {
        &self.source
    }
}

impl LocaleAware for LocaleExtractor {
    fn get_locale(&self) -> &Locale {
        &self.0
    }

    fn get_locale_source(&self) -> &LocaleSource {
        // LocaleExtractor doesn't have source info, return default
        &LocaleSource::Default
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, Method, Uri};

    #[test]
    fn test_parse_accept_language() {
        assert_eq!(
            parse_accept_language("en-US,en;q=0.9,vi;q=0.8"),
            Some("en".to_string())
        );
        
        assert_eq!(
            parse_accept_language("vi,en-US;q=0.8"),
            Some("vi".to_string())
        );
        
        assert_eq!(
            parse_accept_language("ja-JP"),
            Some("ja".to_string())
        );
    }

    #[test]
    fn test_normalize_locale() {
        assert_eq!(normalize_locale("en-US"), "en");
        assert_eq!(normalize_locale("vi-VN"), "vi");
        assert_eq!(normalize_locale("EN"), "en");
        assert_eq!(normalize_locale("Vi"), "vi");
    }

    #[tokio::test]
    async fn test_locale_extraction_from_query() {
        let query = LocaleQuery {
            lang: Some("vi".to_string()),
            locale: None,
        };
        
        let locale_str = extract_locale_from_query(&query);
        assert_eq!(locale_str, Some("vi".to_string()));
    }

    #[tokio::test]
    async fn test_locale_extraction_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert("accept-language", HeaderValue::from_static("vi,en;q=0.8"));
        
        let locale_info = extract_locale_info(&headers, None).await.unwrap();
        assert_eq!(locale_info.locale, Locale::Vi);
        assert!(matches!(locale_info.source, LocaleSource::Header));
    }

    #[tokio::test]
    async fn test_default_locale() {
        let headers = HeaderMap::new();
        
        let locale_info = extract_locale_info(&headers, None).await.unwrap();
        assert_eq!(locale_info.locale, Locale::En);
        assert!(matches!(locale_info.source, LocaleSource::Default));
    }

    #[test]
    fn test_locale_aware_trait() {
        let locale_info = LocaleInfo {
            locale: Locale::Vi,
            source: LocaleSource::Header,
            fallback: Some(Locale::En),
        };

        assert!(locale_info.is_vietnamese());
        assert!(!locale_info.is_english());
        assert_eq!(locale_info.get_locale(), &Locale::Vi);
    }
} 