//! Logic for the OIDC Discovery endpoint (`/.well-known/openid-configuration`).
//!
//! Returns the configuration metadata for this OIDC provider, allowing clients
//! to discover endpoint URLs and supported features.

use crate::AppState;
use axum::{Json, extract::State};
use serde::Serialize;
use std::sync::Arc;

/// Structure representing the OIDC Discovery document.
#[derive(Serialize, Debug)]
pub struct OIDCConfig {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    grant_types_supported: Vec<String>,
}

/// Handler for the OIDC Discovery endpoint.
///
/// Returns the configuration metadata for this OIDC provider.
#[tracing::instrument(skip(state))]
pub async fn openid_configuration(State(state): State<Arc<AppState>>) -> Json<OIDCConfig> {
    tracing::debug!("Serving default OIDC discovery configuration");
    let config = OIDCConfig {
        issuer: state.settings.issuer.clone(),
        authorization_endpoint: format!(
            "{}{}{}",
            state.settings.issuer, state.settings.context_path, state.settings.endpoints.authorize
        ),
        token_endpoint: format!(
            "{}{}{}",
            state.settings.issuer, state.settings.context_path, state.settings.endpoints.token
        ),
        userinfo_endpoint: format!(
            "{}{}{}",
            state.settings.issuer, state.settings.context_path, state.settings.endpoints.userinfo
        ),
        jwks_uri: format!(
            "{}{}{}",
            state.settings.issuer, state.settings.context_path, state.settings.endpoints.jwks
        ),
        response_types_supported: vec!["code".to_string()],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["RS256".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "client_credentials".to_string(),
        ],
    };
    Json(config)
}

use crate::config::SecondaryWellKnownConfiguration;

/// Handler for a secondary OIDC Discovery endpoint.
///
/// Returns the configuration metadata for this OIDC provider, with customized hosts.
#[tracing::instrument(skip(state, secondary))]
pub async fn secondary_openid_configuration(
    State(state): State<Arc<AppState>>,
    secondary: SecondaryWellKnownConfiguration,
) -> Json<OIDCConfig> {
    tracing::debug!("Serving secondary OIDC discovery configuration for path: {}", secondary.path);
    let config = OIDCConfig {
        issuer: state.settings.issuer.clone(),
        authorization_endpoint: format!(
            "{}{}{}",
            secondary.authorization_host, state.settings.context_path, state.settings.endpoints.authorize
        ),
        token_endpoint: format!(
            "{}{}{}",
            secondary.token_host, state.settings.context_path, state.settings.endpoints.token
        ),
        userinfo_endpoint: format!(
            "{}{}{}",
            secondary.userinfo_host, state.settings.context_path, state.settings.endpoints.userinfo
        ),
        jwks_uri: format!(
            "{}{}{}",
            secondary.jwks_host, state.settings.context_path, state.settings.endpoints.jwks
        ),
        response_types_supported: vec!["code".to_string()],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["RS256".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "client_credentials".to_string(),
        ],
    };
    Json(config)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;
    use crate::key::KeyState;
    use moka::future::Cache;

    #[tokio::test]
    async fn test_openid_configuration() {
        let private_key_pem = std::fs::read_to_string("test/private_key.pem").unwrap();
        let key_state = KeyState::new(&private_key_pem);

        let settings = Settings {
            issuer: "http://test-issuer".to_string(),
            context_path: "/oidc".to_string(),
            endpoints: crate::config::EndpointConfig {
                authorize: "/auth".to_string(),
                token: "/tkn".to_string(),
                userinfo: "/uinfo".to_string(),
                jwks: "/keys".to_string(),
                well_known: "/.well-known/openid-configuration".to_string(),
            },
            ..Settings::default()
        };

        let state = Arc::new(AppState {
            settings,
            jwks_cache: Cache::builder().build(),
            auth_code_cache: Cache::builder().build(),
            key_state,
        });

        let Json(config) = openid_configuration(State(state)).await;

        assert_eq!(config.issuer, "http://test-issuer");
        assert_eq!(config.authorization_endpoint, "http://test-issuer/oidc/auth");
        assert_eq!(config.token_endpoint, "http://test-issuer/oidc/tkn");
        assert_eq!(config.userinfo_endpoint, "http://test-issuer/oidc/uinfo");
        assert_eq!(config.jwks_uri, "http://test-issuer/oidc/keys");
    }
}
