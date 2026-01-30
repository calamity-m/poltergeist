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
    tracing::info!(audit = true, "Received token request: grant_type={}", payload.grant_type);
    match payload.grant_type.as_str() {
        "client_credentials" => handle_client_credentials(state, payload).await,
        "authorization_code" => handle_authorization_code(state, payload).await,
        _ => {
            tracing::warn!("Unsupported grant type: {}", payload.grant_type);
            Err((
                StatusCode::BAD_REQUEST,
                format!("unsupported_grant_type: {}", payload.grant_type),
            ))
        }
    }
}

async fn handle_authorization_code(
    state: Arc<AppState>,
    payload: TokenRequest,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    let code = payload.code.ok_or_else(|| {
        tracing::warn!("Missing code in authorization_code grant request");
        (
            StatusCode::BAD_REQUEST,
            "missing code for authorization_code grant".to_string(),
        )
    })?;

    // Retrieve user identity from cache
    let user_identity = state.auth_code_cache.get(&code).await.ok_or_else(|| {
        tracing::warn!("Invalid or expired authorization code: {}", code);
        (
            StatusCode::BAD_REQUEST,
            "invalid or expired authorization code".to_string(),
        )
    })?;

    tracing::info!(
        audit = true,
        "Exchanging code for client: {}, subject: {}",
        user_identity.client_id,
        user_identity.sub
    );

    // Remove code from cache after use (one-time use)
    state.auth_code_cache.invalidate(&code).await;

    // Find the client to get its configured audience
    let client = state
        .settings
        .clients
        .iter()
        .find(|c| c.client_id == user_identity.client_id);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires_in = 3600;

    let aud = client
        .and_then(|c| c.audience.clone())
        .unwrap_or_else(|| user_identity.client_id.clone());

    tracing::debug!("Issuing tokens with audience: {}", aud);

    let claims = Claims {
        sub: user_identity.sub.clone(),
        aud,
        iss: state.settings.issuer.clone(),
        iat: now,
        exp: now + expires_in,
        groups: user_identity.groups.clone(),
    };

    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("poltergeist".to_string());

    let token_string = encode(&header, &claims, &state.key_state.encoding_key).map_err(|e| {
        tracing::error!("Failed to encode JWT: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    tracing::info!(
        audit = true,
        "Tokens successfully issued for client: {}",
        user_identity.client_id
    );

    Ok(Json(TokenResponse {
        access_token: token_string.clone(),
        id_token: token_string,
        expires_in,
    }))
}

async fn handle_client_credentials(
    state: Arc<AppState>,
    payload: TokenRequest,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    let client_id = payload.client_id.ok_or_else(|| {
        tracing::warn!("Missing client_id for client_credentials grant");
        (
            StatusCode::BAD_REQUEST,
            "missing client_id for client_credentials grant".to_string(),
        )
    })?;
    let client_secret = payload.client_secret.ok_or_else(|| {
        tracing::warn!("Missing client_secret for client_credentials grant");
        (
            StatusCode::BAD_REQUEST,
            "missing client_secret for client_credentials grant".to_string(),
        )
    })?;

    tracing::info!(audit = true, "Authenticating client_credentials for: {}", client_id);

    // Find the client in the static configuration
    let client = state
        .settings
        .clients
        .iter()
        .find(|c| c.client_id == client_id && c.client_secret == client_secret)
        .ok_or_else(|| {
            tracing::warn!(audit = true, "Invalid client credentials for: {}", client_id);
            (
                StatusCode::UNAUTHORIZED,
                "invalid client credentials".to_string(),
            )
        })?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires_in = 3600;

    let aud = client
        .audience
        .clone()
        .unwrap_or_else(|| client.client_id.clone());

    tracing::debug!("Issuing M2M tokens with audience: {}", aud);

    let claims = Claims {
        sub: client.client_id.clone(),
        aud,
        iss: state.settings.issuer.clone(),
        iat: now,
        exp: now + expires_in,
        groups: client.groups.clone(),
    };

    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("poltergeist".to_string());

    let token_string = encode(&header, &claims, &state.key_state.encoding_key).map_err(|e| {
        tracing::error!("Failed to encode M2M JWT: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    tracing::info!(audit = true, "M2M tokens successfully issued for client: {}", client_id);

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
                audience: None,
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
                audience: None,
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

    #[tokio::test]
    async fn test_handle_client_credentials_custom_audience() {
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
                audience: Some("custom-audience".to_string()),
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
        
        let token_data = jsonwebtoken::dangerous::insecure_decode::<Claims>(&response.access_token).unwrap();
        
        assert_eq!(token_data.claims.aud, "custom-audience");
    }

    #[tokio::test]
    async fn test_handle_authorization_code_custom_audience() {
        let private_key_pem = std::fs::read_to_string("test/private_key.pem").unwrap();
        let key_state = KeyState::new(&private_key_pem);

        let settings = Settings {
            issuer: "http://localhost:8080".to_string(),
            grant_types_supported: vec!["authorization_code".to_string()],
            port: 8080,
            upstream_oidc_url: "http://upstream".to_string(),
            upstream_jwks_url: "http://upstream/jwks".to_string(),
            validate_upstream_token: false,
            private_key_path: "test/private_key.pem".to_string(),
            clients: vec![StaticClient {
                client_id: "web-app".to_string(),
                client_secret: "secret".to_string(),
                groups: vec![],
                audience: Some("custom-app-aud".to_string()),
            }],
        };

        let auth_code_cache = Cache::builder().build();
        auth_code_cache.insert("test-code".to_string(), crate::UserIdentity {
            sub: "test-user".to_string(),
            email: "test@example.com".to_string(),
            groups: vec!["admin".to_string()],
            client_id: "web-app".to_string(),
        }).await;

        let state = Arc::new(AppState {
            settings,
            auth_code_cache,
            jwks_cache: Cache::builder().build(),
            key_state,
        });

        let payload = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some("test-code".to_string()),
            code_verifier: None,
            client_id: Some("web-app".to_string()),
            client_secret: None,
        };

        let Json(response) = handle_authorization_code(state, payload).await.unwrap();
        
        let token_data = jsonwebtoken::dangerous::insecure_decode::<Claims>(&response.access_token).unwrap();
        
        assert_eq!(token_data.claims.aud, "custom-app-aud");
        assert_eq!(token_data.claims.sub, "test-user");
    }

    #[tokio::test]
    async fn test_handle_client_credentials_default_audience() {
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
                client_id: "default-client".to_string(),
                client_secret: "secret".to_string(),
                groups: vec![],
                audience: None, // No audience set
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
            client_id: Some("default-client".to_string()),
            client_secret: Some("secret".to_string()),
        };

        let Json(response) = handle_client_credentials(state, payload).await.unwrap();
        
        let token_data = jsonwebtoken::dangerous::insecure_decode::<Claims>(&response.access_token).unwrap();
        
        assert_eq!(token_data.claims.aud, "default-client");
    }
}