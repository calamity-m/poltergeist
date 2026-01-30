//! Configuration management for Poltergeist.
//!
//! Handles loading settings from `config.yaml`.

use serde::{Deserialize, Serialize};

/// Application configuration settings.
#[derive(Clone, Deserialize)]
pub struct Settings {
    /// The base URL identifying this OIDC provider (e.g., "http://localhost:8080").
    #[serde(default = "default_issuer")]
    pub issuer: String,
    /// List of OAuth 2.0 grant types supported (e.g., ["authorization_code", "client_credentials"]).
    #[serde(default = "default_grant_types")]
    pub grant_types_supported: Vec<String>,
    /// Port number the server will listen on.
    #[serde(default = "default_port")]
    pub port: u16,
    /// URL to the upstream OIDC provider's authorization endpoint.
    /// Used for redirecting unauthenticated users.
    #[serde(default = "default_upstream_oidc")]
    pub upstream_oidc_url: String,
    /// URL to the upstream OIDC provider's JWKS endpoint.
    /// Used for validating upstream tokens.
    #[serde(default = "default_upstream_jwks")]
    pub upstream_jwks_url: String,
    /// Whether to strictly validate the signature of the upstream token.
    /// If false, the token is decoded without signature verification.
    #[serde(default = "default_validate_upstream")]
    pub validate_upstream_token: bool,
    /// Path to the RSA private key (PEM format) used for signing tokens.
    #[serde(default = "default_key_path")]
    pub private_key_path: String,
    /// Default token expiration time in seconds.
    #[serde(default = "default_token_expiry")]
    pub token_expires_in: u64,
    /// Static clients for M2M (client_credentials) flow.
    #[serde(default)]
    pub private_clients: Vec<PrivateClient>,
    /// Static clients for Browser to service (authorization_code) flow.
    #[serde(default)]
    pub public_clients: Vec<PublicClient>,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
}

fn default_issuer() -> String {
    "http://localhost:8080".to_string()
}
fn default_grant_types() -> Vec<String> {
    vec![
        "authorization_code".to_string(),
        "client_credentials".to_string(),
    ]
}
fn default_port() -> u16 {
    8080
}
fn default_upstream_oidc() -> String {
    "http://localhost:8081/login".to_string()
}
fn default_upstream_jwks() -> String {
    "http://localhost:8081/.well-known/jwks.json".to_string()
}
fn default_validate_upstream() -> bool {
    false
}
fn default_key_path() -> String {
    "test/private_key.pem".to_string()
}
fn default_token_expiry() -> u64 {
    3600
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            issuer: default_issuer(),
            grant_types_supported: default_grant_types(),
            port: default_port(),
            upstream_oidc_url: default_upstream_oidc(),
            upstream_jwks_url: default_upstream_jwks(),
            validate_upstream_token: default_validate_upstream(),
            private_key_path: default_key_path(),
            token_expires_in: default_token_expiry(),
            private_clients: Vec::new(),
            public_clients: Vec::new(),
            telemetry: TelemetryConfig::default(),
        }
    }
}

/// Represents a static OAuth2 client for service-to-service communication.
#[derive(Clone, Deserialize)]
pub struct PrivateClient {
    /// The client's unique identifier.
    pub client_id: String,
    /// The client's secret.
    pub client_secret: String,
    /// The audience to be included in the tokens issued for this client.
    /// If not provided, a default might be used.
    pub audience: String,
}

/// Represents a static OAuth2 client for browser-to-service communication.
#[derive(Clone, Deserialize)]
pub struct PublicClient {
    /// The client's unique identifier.
    pub client_id: String,
    /// The audience to be included in the tokens issued for this client.
    /// If not provided, a default might be used.
    pub audience: String,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LoggingFormat {
    /// JSON format - structured logging suitable for log aggregation systems
    ///
    /// Produces compact, machine-readable JSON output ideal for production
    /// environments and log processing pipelines like ELK stack, Fluentd, etc.
    ///
    /// Default.
    #[default]
    Json,
    /// Pretty format - human-readable output for development
    ///
    /// Produces colorized, indented output that's easier to read during
    /// development and debugging. Not recommended for production use.
    Pretty,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    #[default]
    Info,
    Debug,
    Trace,
    Warn,
    Error,
}

impl From<LogLevel> for tracing::Level {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Trace => tracing::Level::TRACE,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Error => tracing::Level::ERROR,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TelemetryConfig {
    /// Output format for log messages
    #[serde(default)]
    pub format: LoggingFormat,

    /// Global log level for the application
    #[serde(default)]
    pub level: LogLevel,

    /// Log level for Axum web framework
    #[serde(default)]
    pub axum_level: LogLevel,

    /// Service name to append to logs
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// Whether to enable OpenTelemetry (OTLP) exporting
    #[serde(default)]
    pub otlp_enabled: bool,
}

fn default_service_name() -> String {
    "poltergeist".to_string()
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            format: Default::default(),
            level: LogLevel::Info,
            axum_level: LogLevel::Info,
            service_name: default_service_name(),
            otlp_enabled: false,
        }
    }
}

/// Loads configuration from the `config.yaml` file.
///
/// # Panics
/// Panics if the configuration file doesn't match the `Settings` structure.
#[tracing::instrument]
pub fn load_config() -> Settings {
    let cfg = config::Config::builder()
        .add_source(config::File::with_name("config").required(false))
        .add_source(
            config::Environment::with_prefix("POLTERGEIST")
                .prefix_separator("_")
                .separator("__"),
        )
        .build()
        .map_err(|e| {
            tracing::error!("Failed to build configuration: {}", e);
            e
        })
        .unwrap();

    match cfg.try_deserialize::<Settings>() {
        Ok(settings) => settings,
        Err(e) => {
            tracing::warn!(
                "Failed to deserialize configuration, using defaults. Error: {}",
                e
            );
            Settings::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_load_config_env_override() {
        // Set an environment variable that should override the yaml config
        unsafe {
            env::set_var("POLTERGEIST_PORT", "9999");
            env::set_var("POLTERGEIST_ISSUER", "http://env-issuer");
        }

        let settings = load_config();

        assert_eq!(settings.port, 9999);
        assert_eq!(settings.issuer, "http://env-issuer");

        // Clean up
        unsafe {
            env::remove_var("POLTERGEIST_PORT");
            env::remove_var("POLTERGEIST_ISSUER");
        }
    }

    #[test]
    fn test_load_config_telemetry_env_override() {
        unsafe {
            env::set_var("POLTERGEIST_TELEMETRY__LEVEL", "debug");
            env::set_var("POLTERGEIST_TELEMETRY__SERVICE_NAME", "env-service");
            env::set_var("POLTERGEIST_TELEMETRY__OTLP_ENABLED", "true");
        }

        let settings = load_config();

        assert!(matches!(settings.telemetry.level, LogLevel::Debug));
        assert_eq!(settings.telemetry.service_name, "env-service");
        assert!(settings.telemetry.otlp_enabled);

        // Clean up
        unsafe {
            env::remove_var("POLTERGEIST_TELEMETRY__LEVEL");
            env::remove_var("POLTERGEIST_TELEMETRY__SERVICE_NAME");
            env::remove_var("POLTERGEIST_TELEMETRY__OTLP_ENABLED");
        }
    }

    #[test]
    fn test_load_config_defaults() {
        // Ensure no relevant env vars are set
        unsafe {
            env::remove_var("POLTERGEIST_PORT");
            env::remove_var("POLTERGEIST_ISSUER");
            env::remove_var("POLTERGEIST_TELEMETRY__LEVEL");
        }

        let settings = load_config();

        assert_eq!(settings.port, 8080);
        assert_eq!(settings.issuer, "http://localhost:8080");
        assert!(matches!(settings.telemetry.level, LogLevel::Info));
        assert!(matches!(settings.telemetry.axum_level, LogLevel::Info));
        assert_eq!(settings.telemetry.service_name, "poltergeist");
    }
}
