use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Middleware and extractor are separate modules

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApiVersion {
    pub major: u32,
    pub minor: u32,
}

impl ApiVersion {
    pub fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }

    pub fn parse(version_str: &str) -> Result<Self, VersionError> {
        let parts: Vec<&str> = version_str.split('.').collect();
        
        if parts.len() != 2 {
            return Err(VersionError::InvalidFormat(version_str.to_string()));
        }

        let major = parts[0].parse::<u32>()
            .map_err(|_| VersionError::InvalidFormat(version_str.to_string()))?;
        
        let minor = parts[1].parse::<u32>()
            .map_err(|_| VersionError::InvalidFormat(version_str.to_string()))?;

        Ok(ApiVersion::new(major, minor))
    }

    pub fn to_string(&self) -> String {
        format!("{}.{}", self.major, self.minor)
    }

    pub fn is_compatible_with(&self, other: &ApiVersion) -> bool {
        // Backward compatibility: same major version, minor >= requested
        self.major == other.major && self.minor >= other.minor
    }
}

impl Default for ApiVersion {
    fn default() -> Self {
        // Latest version
        ApiVersion::new(1, 0)
    }
}

impl std::fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

#[derive(Debug, Clone)]
pub enum VersionSource {
    Header,
    Token,
    Default,
}

#[derive(Debug, Clone)]
pub struct VersionInfo {
    pub version: ApiVersion,
    pub source: VersionSource,
}

impl Default for VersionInfo {
    fn default() -> Self {
        Self {
            version: ApiVersion::default(),
            source: VersionSource::Default,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPayload {
    pub version: Option<String>,
    pub locale: Option<String>,
    // Other token fields...
    pub user_id: Option<String>,
    pub exp: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum VersionError {
    #[error("Invalid version format: {0}")]
    InvalidFormat(String),
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(String),
    #[error("Version extraction failed: {0}")]
    ExtractionFailed(String),
}

impl IntoResponse for VersionError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            VersionError::InvalidFormat(msg) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid version format: {}", msg)
            ),
            VersionError::UnsupportedVersion(msg) => (
                StatusCode::NOT_ACCEPTABLE,
                format!("Unsupported version: {}", msg)
            ),
            VersionError::ExtractionFailed(msg) => (
                StatusCode::BAD_REQUEST,
                format!("Version extraction failed: {}", msg)
            ),
        };

        let body = Json(serde_json::json!({
            "error": "VERSION_ERROR",
            "message": error_message,
            "timestamp": chrono::Utc::now().to_rfc3339()
        }));

        (status, body).into_response()
    }
}

pub struct VersionRegistry {
    supported_versions: HashMap<ApiVersion, bool>,
    latest_version: ApiVersion,
}

impl VersionRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            supported_versions: HashMap::new(),
            latest_version: ApiVersion::default(),
        };

        // Register supported versions
        registry.register_version(ApiVersion::new(1, 0), true);
        // Future versions can be added here
        // registry.register_version(ApiVersion::new(1, 1), true);
        // registry.register_version(ApiVersion::new(2, 0), true);

        registry
    }

    pub fn register_version(&mut self, version: ApiVersion, active: bool) {
        self.supported_versions.insert(version.clone(), active);
        
        // Update latest version if this version is newer
        if version.major > self.latest_version.major || 
           (version.major == self.latest_version.major && version.minor > self.latest_version.minor) {
            self.latest_version = version;
        }
    }

    pub fn is_supported(&self, version: &ApiVersion) -> bool {
        // Check if exact version is supported
        if let Some(&active) = self.supported_versions.get(version) {
            return active;
        }

        // Check for backward compatibility
        for (supported_version, &active) in &self.supported_versions {
            if active && supported_version.is_compatible_with(version) {
                return true;
            }
        }

        false
    }

    pub fn get_latest_version(&self) -> &ApiVersion {
        &self.latest_version
    }

    pub fn get_supported_versions(&self) -> Vec<ApiVersion> {
        self.supported_versions
            .iter()
            .filter_map(|(version, &active)| if active { Some(version.clone()) } else { None })
            .collect()
    }

    pub fn resolve_version(&self, requested: &ApiVersion) -> Result<ApiVersion, VersionError> {
        if self.is_supported(requested) {
            Ok(requested.clone())
        } else {
            // Try to find a compatible version
            for (supported_version, &active) in &self.supported_versions {
                if active && supported_version.is_compatible_with(requested) {
                    return Ok(supported_version.clone());
                }
            }
            Err(VersionError::UnsupportedVersion(requested.to_string()))
        }
    }
}

pub fn extract_version_from_headers(headers: &HeaderMap) -> Option<String> {
    headers.get("api-version")
        .and_then(|header_value| header_value.to_str().ok())
        .map(|s| s.to_string())
}

pub fn extract_version_from_token(token: &str) -> Result<Option<String>, VersionError> {
    // Simple pattern matching for demo purposes
    if token.contains("v1.0") {
        return Ok(Some("1.0".to_string()));
    }
    if token.contains("v1.1") {
        return Ok(Some("1.1".to_string()));
    }
    // If pattern not found, return None
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        assert_eq!(ApiVersion::parse("1.0").unwrap(), ApiVersion::new(1, 0));
        assert_eq!(ApiVersion::parse("2.5").unwrap(), ApiVersion::new(2, 5));
        assert!(ApiVersion::parse("invalid").is_err());
        assert!(ApiVersion::parse("1.0.0").is_err());
    }

    #[test]
    fn test_version_compatibility() {
        let v1_0 = ApiVersion::new(1, 0);
        let v1_1 = ApiVersion::new(1, 1);
        let v2_0 = ApiVersion::new(2, 0);

        assert!(v1_1.is_compatible_with(&v1_0));
        assert!(!v1_0.is_compatible_with(&v1_1));
        assert!(!v2_0.is_compatible_with(&v1_0));
    }

    #[test]
    fn test_version_registry() {
        let mut registry = VersionRegistry::new();
        registry.register_version(ApiVersion::new(1, 1), true);

        assert!(registry.is_supported(&ApiVersion::new(1, 0)));
        assert!(registry.is_supported(&ApiVersion::new(1, 1)));
        assert!(!registry.is_supported(&ApiVersion::new(2, 0)));
    }
} 