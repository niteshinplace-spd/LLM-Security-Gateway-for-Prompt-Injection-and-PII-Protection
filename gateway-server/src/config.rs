//! Configuration loading, environment overrides, and SSRF validation.

use serde::Deserialize;
use std::env;
use std::fs;
use std::path::Path;
use url::Url;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub timeout_seconds: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            timeout_seconds: 60,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
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
pub struct SecurityConfig {
    pub allow_localhost: bool,
    pub block_cloud_metadata: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            allow_localhost: true,
            block_cloud_metadata: true,
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            upstream: UpstreamConfig::default(),
            security: SecurityConfig::default(),
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

        // Validate upstream URL against SSRF rules
        config.validate_upstream_url()?;

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
