//! Configuration management for Poltergeist.
//!
//! Handles loading settings from `config.yaml`.

use serde::Deserialize;

/// Application configuration settings.
#[derive(Clone, Deserialize)]
pub struct Settings {
    /// The base URL identifying this OIDC provider (e.g., "http://localhost:8080").
    pub issuer: String,
    /// List of OAuth 2.0 grant types supported (e.g., ["authorization_code", "client_credentials"]).
    pub grant_types_supported: Vec<String>,
    /// Port number the server will listen on.
    pub port: u16,
    /// URL to the upstream OIDC provider's authorization endpoint.
    /// Used for redirecting unauthenticated users.
    pub upstream_oidc_url: String,
    /// URL to the upstream OIDC provider's JWKS endpoint.
    /// Used for validating upstream tokens.
    pub upstream_jwks_url: String,
    /// Whether to strictly validate the signature of the upstream token.
    /// If false, the token is decoded without signature verification.
    pub validate_upstream_token: bool,
    /// Path to the RSA private key (PEM format) used for signing tokens.
    pub private_key_path: String,
    /// Static clients for M2M (client_credentials) flow.
    pub clients: Vec<StaticClient>,
}

/// Represents a static OAuth2 client for service-to-service communication.
#[derive(Clone, Deserialize)]
pub struct StaticClient {
    /// The client's unique identifier.
    pub client_id: String,
    /// The client's secret.
    pub client_secret: String,
    /// The groups (permissions) associated with this client.
    pub groups: Vec<String>,
    /// The audience to be included in the tokens issued for this client.
    /// If not provided, a default might be used.
    pub audience: Option<String>,
}

/// Loads configuration from the `config.yaml` file.
///
/// # Panics
/// Panics if the configuration file cannot be found or if it doesn't match the `Settings` structure.
pub fn load_config() -> Settings {
    let cfg = config::Config::builder()
        .add_source(config::File::with_name("config"))
        .build()
        .map_err(|e| {
            tracing::error!("Failed to build configuration: {}", e);
            e
        })
        .unwrap();

    cfg.try_deserialize::<Settings>()
        .map_err(|e| {
            tracing::error!("Failed to deserialize configuration: {}", e);
            e
        })
        .unwrap()
}