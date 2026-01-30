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
}

/// Loads configuration from the `config.yaml` file.
///
/// # Panics
/// Panics if the configuration file cannot be found or if it doesn't match the `Settings` structure.
pub fn load_config() -> Settings {
    config::Config::builder()
        .add_source(config::File::with_name("config"))
        .build()
        .unwrap()
        .try_deserialize::<Settings>()
        .unwrap()
}