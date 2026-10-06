//! Configuration loading, environment overrides, and SSRF validation.

use axum::http::header;
use axum::http::HeaderMap;
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::Path;
use tracing::warn;
use url::Url;

use crate::error::GatewayError;

pub use crate::rag::RagConfig;

/// Threat categories for governance checks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ThreatCategory {
    NetworkAccess,
    ToolExecution,
    McpServer,
    RagPipeline,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub timeout_seconds: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            timeout_seconds: 60,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct UpstreamConfig {
    pub base_url: String,
    pub chat_endpoint: String,
    pub default_model: String,
    pub api_key: String,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:11434".to_string(),
            chat_endpoint: "/v1/chat/completions".to_string(),
            default_model: "llama3.2:3b".to_string(),
            api_key: String::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub allow_localhost: bool,
    pub block_cloud_metadata: bool,
    pub block_secrets: bool,
    pub require_auth: bool,
    pub auth_token: Option<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            allow_localhost: true,
            block_cloud_metadata: true,
            block_secrets: false,
            require_auth: false,
            auth_token: None,
        }
    }
}

impl SecurityConfig {
    /// Enforces authentication when `require_auth` is true.
    /// Returns Ok(()) if authentication succeeds, otherwise a `GatewayError::SecurityBlocked`.
    pub fn enforce_auth(&self, headers: &HeaderMap) -> Result<(), GatewayError> {
        if !self.require_auth {
            return Ok(());
        }
        let expected = self.auth_token.as_ref().ok_or_else(|| GatewayError::SecurityBlocked {
            reason: "Authentication token not configured".into(),
            category: "Authentication".into(),
        })?;
        let provided = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        let token = provided.map(|h| {
            let lower = h.to_ascii_lowercase();
            if lower.starts_with("bearer ") {
                h[7..].trim()
            } else {
                h.trim()
            }
        });
        if token != Some(expected.as_str()) {
            return Err(GatewayError::SecurityBlocked {
                reason: "Missing or invalid auth token".into(),
                category: "Authentication".into(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GovernanceConfig {
    pub default_deny: bool,
    pub allowlist: Vec<String>,
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            default_deny: true,
            allowlist: Vec::new(),
        }
    }
}

impl GovernanceConfig {
    /// Enforces the default‑deny policy.
    /// Returns Ok(()) if the request is allowed, otherwise a `GatewayError::SecurityBlocked`.
    pub fn check_request(&self, category: ThreatCategory, target: &str) -> Result<(), GatewayError> {
        // If default deny is disabled, everything passes.
        if !self.default_deny {
            return Ok(());
        }
        // Allowlist match – exact string comparison.
        if self.allowlist.iter().any(|allowed| allowed == target) {
            return Ok(());
        }
        // Deny by default.
        let reason = format!("Blocked {:?} request to '{}' by default‑deny policy", category, target);
        warn!(category = ?category, target = %target, "Governance block");
        Err(GatewayError::SecurityBlocked {
            reason,
            category: format!("{:?}", category),
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub security: SecurityConfig,
    pub governance: GovernanceConfig,
    pub rag: RagConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            upstream: UpstreamConfig::default(),
            security: SecurityConfig::default(),
            governance: GovernanceConfig::default(),
            rag: RagConfig::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to parse TOML configuration: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("Invalid upstream URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("SSRF validation failed: {0}")]
    SsrfBlocked(String),
}

impl AppConfig {
    /// Load configuration from file (e.g. config.toml) and overlay environment variables.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let mut config = if path.as_ref().exists() {
            let content = fs::read_to_string(path)?;
            toml::from_str::<AppConfig>(&content)?
        } else {
            AppConfig::default()
        };

        // Apply environment variable overrides (env vars WIN over toml)
        if let Ok(host) = env::var("GATEWAY_HOST") {
            config.server.host = host;
        }
        if let Ok(port) = env::var("GATEWAY_PORT") {
            if let Ok(p) = port.parse::<u16>() {
                config.server.port = p;
            }
        }
        if let Ok(timeout) = env::var("GATEWAY_TIMEOUT_SECONDS") {
            if let Ok(t) = timeout.parse::<u64>() {
                config.server.timeout_seconds = t;
            }
        }
        if let Ok(url) = env::var("UPSTREAM_BASE_URL") {
            config.upstream.base_url = url;
        }
        if let Ok(endpoint) = env::var("UPSTREAM_CHAT_ENDPOINT") {
            config.upstream.chat_endpoint = endpoint;
        }
        if let Ok(model) = env::var("UPSTREAM_DEFAULT_MODEL") {
            config.upstream.default_model = model;
        }
        if let Ok(key) = env::var("UPSTREAM_API_KEY") {
            config.upstream.api_key = key;
        }
        if let Ok(allow_local) = env::var("ALLOW_LOCALHOST") {
            if let Ok(b) = allow_local.parse::<bool>() {
                config.security.allow_localhost = b;
            }
        }
        if let Ok(block_meta) = env::var("BLOCK_CLOUD_METADATA") {
            if let Ok(b) = block_meta.parse::<bool>() {
                config.security.block_cloud_metadata = b;
            }
        }

        // Authentication and Governance env var handling
        if let Ok(require_auth) = env::var("REQUIRE_AUTH") {
            if let Ok(b) = require_auth.parse::<bool>() {
                config.security.require_auth = b;
            }
        }
        if let Ok(token) = env::var("AUTH_TOKEN") {
            if !token.is_empty() {
                config.security.auth_token = Some(token);
            }
        }
        if let Ok(default_deny) = env::var("GOVERNANCE_DEFAULT_DENY") {
            if let Ok(b) = default_deny.parse::<bool>() {
                config.governance.default_deny = b;
            }
        }
        if let Ok(allowlist) = env::var("GOVERNANCE_ALLOWLIST") {
            // comma‑separated list of allowed targets (e.g., URLs)
            let list: Vec<String> = allowlist
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            config.governance.allowlist = list;
        }

        // RAG environment variable overrides
        if let Ok(enabled) = env::var("RAG_ENABLED") {
            if let Ok(b) = enabled.parse::<bool>() {
                config.rag.enabled = b;
            }
        }
        if let Ok(dim) = env::var("RAG_VECTOR_DIM") {
            if let Ok(d) = dim.parse::<usize>() {
                config.rag.vector_dim = d;
            }
        }
        if let Ok(top_k) = env::var("RAG_TOP_K") {
            if let Ok(k) = top_k.parse::<usize>() {
                config.rag.top_k = k;
            }
        }
        if let Ok(index_path) = env::var("RAG_INDEX_PATH") {
            config.rag.index_path = std::path::PathBuf::from(index_path);
        }
        if let Ok(model) = env::var("RAG_EMBEDDING_MODEL") {
            config.rag.embedding_model = model;
        }

        Ok(config)
    }

    /// Validates upstream URL to block SSRF and malicious redirects.
    pub fn validate_upstream_url(&self) -> Result<(), ConfigError> {
        let parsed = Url::parse(&self.upstream.base_url)?;

        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(ConfigError::SsrfBlocked(format!(
                "Unsupported URL scheme: '{}'. Only http and https are allowed.",
                scheme
            )));
        }

        let host = parsed.host_str().unwrap_or("");
        if host.is_empty() {
            return Err(ConfigError::SsrfBlocked(
                "Upstream URL host cannot be empty".to_string(),
            ));
        }

        // 1. Check cloud metadata IP (169.254.169.254 or link-local 169.254.x.x)
        if self.security.block_cloud_metadata {
            if host.starts_with("169.254.") || host.eq_ignore_ascii_case("metadata.google.internal") {
                return Err(ConfigError::SsrfBlocked(format!(
                    "Access to cloud metadata address '{}' is strictly prohibited",
                    host
                )));
            }
        }

        // 2. Check localhost if disallowed
        if !self.security.allow_localhost {
            if host == "127.0.0.1"
                || host == "localhost"
                || host == "::1"
                || host.starts_with("127.")
            {
                return Err(ConfigError::SsrfBlocked(format!(
                    "Access to localhost '{}' is disabled in current configuration",
                    host
                )));
            }
        }

        Ok(())
    }

    /// Full upstream URL for chat completions.
    pub fn upstream_chat_url(&self) -> String {
        let base = self.upstream.base_url.trim_end_matches('/');
        let endpoint = self.upstream.chat_endpoint.trim_start_matches('/');
        format!("{}/{}", base, endpoint)
    }

    /// Authorization header value if an API key is configured.
    pub fn authorization_header(&self) -> Option<String> {
        let key = self.upstream.api_key.trim();
        if key.is_empty() {
            None
        } else {
            Some(format!("Bearer {}", key))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_localhost_url() {
        let config = AppConfig::default();
        assert!(config.validate_upstream_url().is_ok());
        assert_eq!(
            config.upstream_chat_url(),
            "http://127.0.0.1:11434/v1/chat/completions"
        );
    }

    #[test]
    fn test_ssrf_metadata_blocked() {
        let mut config = AppConfig::default();
        config.upstream.base_url = "http://169.254.169.254/latest/meta-data".to_string();
        let res = config.validate_upstream_url();
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("metadata"));
    }

    #[test]
    fn test_localhost_blocked_when_disabled() {
        let mut config = AppConfig::default();
        config.security.allow_localhost = false;
        config.upstream.base_url = "http://127.0.0.1:8000".to_string();
        let res = config.validate_upstream_url();
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("localhost"));
    }
}
