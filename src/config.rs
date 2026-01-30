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
    /// Default token expiration time in seconds.
    pub token_expires_in: u64,
    /// Static clients for M2M (client_credentials) flow.
    pub clients: Vec<StaticClient>,
}

#[derive(Clone, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ClientType {
    Public,
    Private,
}

/// Represents a static OAuth2 client for service-to-service communication.
#[derive(Clone, Deserialize)]
pub struct StaticClient {
    /// The client's unique identifier.
    pub client_id: String,
    /// The client's secret.
    pub client_secret: String,
    /// The audience to be included in the tokens issued for this client.
    /// If not provided, a default might be used.
    pub audience: String,
    /// The type of client (public or private).
    pub client_type: ClientType,
}

/// Loads configuration from the `config.yaml` file.
///
/// # Panics
/// Panics if the configuration file cannot be found or if it doesn't match the `Settings` structure.
#[tracing::instrument]
pub fn load_config() -> Settings {
    let cfg = config::Config::builder()
        .add_source(config::File::with_name("config"))
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

    cfg.try_deserialize::<Settings>()
        .map_err(|e| {
            tracing::error!("Failed to deserialize configuration: {}", e);
            e
        })
        .unwrap()
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
}
