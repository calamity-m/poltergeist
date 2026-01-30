//! Logic for the `/token` endpoint.
//!
//! Handles the exchange of authorization codes (or client credentials) for access and ID tokens.

use crate::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use jsonwebtoken::{encode, Header};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Parameters for the token exchange request.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct TokenRequest {
    /// The grant type (e.g., "authorization_code" or "client_credentials").
    grant_type: String,
    /// The authorization code received from the `/authorize` endpoint.
    code: Option<String>,
    /// PKCE code verifier (currently ignored but part of the spec).
    code_verifier: Option<String>,
    /// Client identifier.
    client_id: Option<String>,
    /// Client secret (for client_credentials flow).
    client_secret: Option<String>,
}

/// The response containing the issued tokens.
#[derive(Serialize, Debug)]
pub struct TokenResponse {
    /// The access token (JWT).
    access_token: String,
    /// The ID token (JWT).
    id_token: String,
    /// Time in seconds until the token expires.
    expires_in: u64,
}

/// JWT claims for the tokens issued by Poltergeist.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject identifier.
    pub sub: String,
    /// Audience.
    pub aud: String,
    /// Issuer.
    pub iss: String,
    /// Expiration time (UNIX timestamp).
    pub exp: u64,
    /// Issued at (UNIX timestamp).
    pub iat: u64,
    /// List of groups/permissions.
    pub groups: Vec<String>,
}

/// Handler for the `/token` endpoint.
///
/// Handles both `authorization_code` and `client_credentials` grant types.
pub async fn token(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    match payload.grant_type.as_str() {
        "client_credentials" => handle_client_credentials(state, payload).await,
        "authorization_code" => {
            // TODO: Implement authorization_code logic
            Err((
                StatusCode::NOT_IMPLEMENTED,
                "authorization_code grant type not yet implemented".to_string(),
            ))
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("unsupported_grant_type: {}", payload.grant_type),
        )),
    }
}

async fn handle_client_credentials(
    state: Arc<AppState>,
    payload: TokenRequest,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    let client_id = payload.client_id.ok_or((
        StatusCode::BAD_REQUEST,
        "missing client_id for client_credentials grant".to_string(),
    ))?;
    let client_secret = payload.client_secret.ok_or((
        StatusCode::BAD_REQUEST,
        "missing client_secret for client_credentials grant".to_string(),
    ))?;

    // Find the client in the static configuration
    let client = state
        .settings
        .clients
        .iter()
        .find(|c| c.client_id == client_id && c.client_secret == client_secret)
        .ok_or((StatusCode::UNAUTHORIZED, "invalid client credentials".to_string()))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires_in = 3600;

    let claims = Claims {
        sub: client.client_id.clone(),
        aud: "camunda-web".to_string(), // Default audience for Camunda
        iss: state.settings.issuer.clone(),
        iat: now,
        exp: now + expires_in,
        groups: client.groups.clone(),
    };

    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("poltergeist".to_string());

    let token_string = encode(&header, &claims, &state.key_state.encoding_key)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(TokenResponse {
        access_token: token_string.clone(),
        id_token: token_string, // For client_credentials, we often return the same token or similar
        expires_in,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Settings, StaticClient};
    use crate::key::KeyState;
    use moka::future::Cache;

    #[tokio::test]
    async fn test_handle_client_credentials_success() {
        let private_key_pem = std::fs::read_to_string("test/private_key.pem").unwrap();
        let key_state = KeyState::new(&private_key_pem);

        let settings = Settings {
            issuer: "http://localhost:8080".to_string(),
            grant_types_supported: vec!["client_credentials".to_string()],
            port: 8080,
            upstream_oidc_url: "http://upstream".to_string(),
            upstream_jwks_url: "http://upstream/jwks".to_string(),
            validate_upstream_token: false,
            private_key_path: "test/private_key.pem".to_string(),
            clients: vec![StaticClient {
                client_id: "test-client".to_string(),
                client_secret: "test-secret".to_string(),
                groups: vec!["test-group".to_string()],
            }],
        };

        let state = Arc::new(AppState {
            settings,
            auth_code_cache: Cache::builder().build(),
            jwks_cache: Cache::builder().build(),
            key_state,
        });

        let payload = TokenRequest {
            grant_type: "client_credentials".to_string(),
            code: None,
            code_verifier: None,
            client_id: Some("test-client".to_string()),
            client_secret: Some("test-secret".to_string()),
        };

        let Json(response) = handle_client_credentials(state, payload).await.unwrap();
        assert!(!response.access_token.is_empty());
        assert_eq!(response.expires_in, 3600);
    }

    #[tokio::test]
    async fn test_handle_client_credentials_invalid_secret() {
        let private_key_pem = std::fs::read_to_string("test/private_key.pem").unwrap();
        let key_state = KeyState::new(&private_key_pem);

        let settings = Settings {
            issuer: "http://localhost:8080".to_string(),
            grant_types_supported: vec!["client_credentials".to_string()],
            port: 8080,
            upstream_oidc_url: "http://upstream".to_string(),
            upstream_jwks_url: "http://upstream/jwks".to_string(),
            validate_upstream_token: false,
            private_key_path: "test/private_key.pem".to_string(),
            clients: vec![StaticClient {
                client_id: "test-client".to_string(),
                client_secret: "test-secret".to_string(),
                groups: vec!["test-group".to_string()],
            }],
        };

        let state = Arc::new(AppState {
            settings,
            auth_code_cache: Cache::builder().build(),
            jwks_cache: Cache::builder().build(),
            key_state,
        });

        let payload = TokenRequest {
            grant_type: "client_credentials".to_string(),
            code: None,
            code_verifier: None,
            client_id: Some("test-client".to_string()),
            client_secret: Some("wrong-secret".to_string()),
        };

        let result = handle_client_credentials(state, payload).await;
        assert!(result.is_err());
        let (status, msg) = result.unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(msg, "invalid client credentials");
    }
}