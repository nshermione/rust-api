use axum::{
    extract::Request,
    http::HeaderMap,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use super::{
    ApiVersion, VersionInfo, VersionSource, VersionRegistry, VersionError,
    extract_version_from_headers, extract_version_from_token
};

#[derive(Clone)]
pub struct VersioningMiddleware {
    registry: Arc<VersionRegistry>,
}

impl VersioningMiddleware {
    pub fn new(registry: VersionRegistry) -> Self {
        Self {
            registry: Arc::new(registry),
        }
    }

    pub fn layer() -> tower::layer::util::Identity {
        tower::layer::util::Identity::new()
    }
}

pub async fn version_middleware(
    mut request: Request,
    next: Next,
) -> Result<Response, VersionError> {
    let headers = request.headers();
    
    // Extract version with priority: header > token > default
    let version_info = extract_version_info(headers).await?;
    
    // Validate version against registry
    let registry = VersionRegistry::new(); // In practice, this should be injected
    let resolved_version = registry.resolve_version(&version_info.version)?;
    
    // Create final version info with resolved version
    let final_version_info = VersionInfo {
        version: resolved_version,
        source: version_info.source,
    };
    
    // Store version info in request extensions for later extraction
    request.extensions_mut().insert(final_version_info);
    
    // Continue to next middleware/handler
    let response = next.run(request).await;
    
    Ok(response)
}

async fn extract_version_info(headers: &HeaderMap) -> Result<VersionInfo, VersionError> {
    // Priority 1: Check api-version header
    if let Some(version_str) = extract_version_from_headers(headers) {
        let version = ApiVersion::parse(&version_str)?;
        return Ok(VersionInfo {
            version,
            source: VersionSource::Header,
        });
    }
    
    // Priority 2: Check Authorization header for token
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = extract_bearer_token(auth_str) {
                if let Ok(Some(version_str)) = extract_version_from_token(token) {
                    let version = ApiVersion::parse(&version_str)?;
                    return Ok(VersionInfo {
                        version,
                        source: VersionSource::Token,
                    });
                }
            }
        }
    }
    
    // Priority 3: Default to latest version
    Ok(VersionInfo {
        version: ApiVersion::default(),
        source: VersionSource::Default,
    })
}

fn extract_bearer_token(auth_header: &str) -> Option<&str> {
    // Accept both "Bearer <token>" and bare "Bearer" (empty token)
    if auth_header == "Bearer" {
        return Some("");
    }
    if auth_header.starts_with("Bearer ") {
        return Some(&auth_header[7..]);
    }
    None
}

// We'll apply middleware directly in main.rs

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, Method, Uri};

    #[tokio::test]
    async fn test_version_extraction_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert("api-version", HeaderValue::from_static("1.0"));
        
        let version_info = extract_version_info(&headers).await.unwrap();
        assert_eq!(version_info.version, ApiVersion::new(1, 0));
        assert!(matches!(version_info.source, VersionSource::Header));
    }

    #[tokio::test]
    async fn test_version_extraction_from_token() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer token.with.v1.0"));
        
        let version_info = extract_version_info(&headers).await.unwrap();
        assert_eq!(version_info.version, ApiVersion::new(1, 0));
        assert!(matches!(version_info.source, VersionSource::Token));
    }

    #[tokio::test]
    async fn test_default_version() {
        let headers = HeaderMap::new();
        
        let version_info = extract_version_info(&headers).await.unwrap();
        assert_eq!(version_info.version, ApiVersion::default());
        assert!(matches!(version_info.source, VersionSource::Default));
    }

    #[test]
    fn test_bearer_token_extraction() {
        assert_eq!(
            extract_bearer_token("Bearer abc123"),
            Some("abc123")
        );
        assert_eq!(
            extract_bearer_token("Basic abc123"),
            None
        );
        assert_eq!(
            extract_bearer_token("Bearer"),
            Some("")
        );
    }
} 