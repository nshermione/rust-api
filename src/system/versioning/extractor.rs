use axum::{
    extract::Request,
    response::{IntoResponse, Response},
    Json,
};

use super::{VersionInfo, ApiVersion, VersionSource};

// Helper function to extract VersionInfo from request
pub fn extract_version_info_from_request(request: &Request) -> Option<VersionInfo> {
    request.extensions().get::<VersionInfo>().cloned()
}

// Extractor for just the ApiVersion
#[derive(Debug, Clone)]
pub struct Version(pub ApiVersion);

impl Version {
    pub fn inner(self) -> ApiVersion {
        self.0
    }
}

impl std::ops::Deref for Version {
    type Target = ApiVersion;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<VersionInfo> for Version {
    fn from(version_info: VersionInfo) -> Self {
        Version(version_info.version)
    }
}

// Simplified version extraction
impl Version {
    pub fn from_request(request: &Request) -> Option<Self> {
        extract_version_info_from_request(request).map(|info| Version(info.version))
    }
}

// Helper trait for version-aware handlers
pub trait VersionAware {
    fn get_version(&self) -> &ApiVersion;
    fn get_version_source(&self) -> &VersionSource;
    fn is_version(&self, major: u32, minor: u32) -> bool {
        let version = self.get_version();
        version.major == major && version.minor == minor
    }
    fn is_at_least_version(&self, major: u32, minor: u32) -> bool {
        let version = self.get_version();
        version.major > major || (version.major == major && version.minor >= minor)
    }
}

impl VersionAware for VersionInfo {
    fn get_version(&self) -> &ApiVersion {
        &self.version
    }

    fn get_version_source(&self) -> &VersionSource {
        &self.source
    }
}

impl VersionAware for Version {
    fn get_version(&self) -> &ApiVersion {
        &self.0
    }

    fn get_version_source(&self) -> &VersionSource {
        // Version extractor doesn't have source info, return default
        &VersionSource::Default
    }
}

// Response helper that includes version info
#[derive(serde::Serialize)]
pub struct VersionedResponse<T: serde::Serialize> {
    pub data: T,
    pub version: String,
    pub source: String,
}

impl<T: serde::Serialize> VersionedResponse<T> {
    pub fn new(data: T, version_info: &VersionInfo) -> Self {
        Self {
            data,
            version: version_info.version.to_string(),
            source: match version_info.source {
                VersionSource::Header => "header".to_string(),
                VersionSource::Token => "token".to_string(),
                VersionSource::Default => "default".to_string(),
            },
        }
    }

    pub fn with_version(data: T, version: &ApiVersion) -> Self {
        Self {
            data,
            version: version.to_string(),
            source: "unknown".to_string(),
        }
    }
}

impl<T: serde::Serialize> IntoResponse for VersionedResponse<T> {
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, Method, Uri};
    
    #[test]
    fn test_version_aware_trait() {
        let version_info = VersionInfo {
            version: ApiVersion::new(1, 2),
            source: VersionSource::Header,
        };

        assert!(version_info.is_version(1, 2));
        assert!(!version_info.is_version(1, 1));
        assert!(version_info.is_at_least_version(1, 0));
        assert!(version_info.is_at_least_version(1, 2));
        assert!(!version_info.is_at_least_version(1, 3));
        assert!(!version_info.is_at_least_version(2, 0));
    }

    #[test]
    fn test_versioned_response() {
        let data = serde_json::json!({"message": "Hello"});
        let version_info = VersionInfo {
            version: ApiVersion::new(1, 0),
            source: VersionSource::Header,
        };

        let response = VersionedResponse::new(data, &version_info);
        
        assert_eq!(response.version, "1.0");
        assert_eq!(response.source, "header");
    }

    #[test]
    fn test_version_wrapper() {
        let version = Version(ApiVersion::new(2, 1));
        
        assert_eq!(version.major, 2);
        assert_eq!(version.minor, 1);
        assert_eq!(version.to_string(), "2.1");
    }
} 