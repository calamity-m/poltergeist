//! Logic for the `/token` endpoint.
//!
//! Handles the exchange of authorization codes (or client credentials) for access and ID tokens.

use crate::AppState;
use crate::downstream;
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use jsonwebtoken::{Header, encode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Parameters for the token exchange request.
#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
pub struct TokenRequest {
    /// The grant type (e.g., "authorization_code" or "client_credentials").
    grant_type: String,
    /// The authorization code received from the `/authorize` endpoint.
    code: Option<String>,
    /// PKCE code verifier (currently ignored but part of the spec).
    code_verifier: Option<String>,
    /// Client identifier.
    pub client_id: String,
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

/// Handler for the `/token` endpoint.
///
/// 1.  Validates the `grant_type` (supports `authorization_code` and `client_credentials`).
/// 2.  Retrieves the user identity:
///     -   For `authorization_code`: Uses the provided code to lookup the user identity
///         in the `auth_code_cache` (originally stored during the `/authorize` flow).
///     -   For `client_credentials`: From the static configuration.
/// 3.  Validates client credentials if necessary.
/// 4.  Mints a new downstream JWT (Access Token & ID Token).
/// 5.  Returns the tokens in a standard OAuth 2.0 JSON response.
#[tracing::instrument(
    skip(state, _headers, payload),
    fields(
        grant_type = payload.grant_type,
        client_id = payload.client_id,
        code = payload.code
    )
)]
pub async fn token(
    State(state): State<Arc<AppState>>,
    _headers: HeaderMap,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    tracing::info!("Received token request: grant_type={}", payload.grant_type);
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
    // Try to find as public client first
    let public_client = state
        .settings
        .public_clients
        .iter()
        .find(|c| c.client_id == payload.client_id);

    let aud = if let Some(c) = public_client {
        c.audience.clone()
    } else {
        // Try private clients
        let private_client = state
            .settings
            .private_clients
            .iter()
            .find(|c| c.client_id == payload.client_id)
            .ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("{} is not a valid client_id", payload.client_id),
                )
            })?;

        // For private clients, we MUST have a secret and it MUST match
        let secret = payload.client_secret.as_deref().ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "client_secret required for confidential client".to_string(),
            )
        })?;

        if private_client.client_secret != secret {
            return Err((
                StatusCode::UNAUTHORIZED,
                "invalid client secret".to_string(),
            ));
        }

        private_client.audience.clone()
    };

    // Try to get identity from cache via code
    let code = payload
        .code
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "no code provided".to_string()))?;

    let context = state.auth_code_cache.get(&code).await.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "invalid or expired code".to_string(),
        )
    })?;

    // Success! remove it from cache (single use)
    state.auth_code_cache.invalidate(&code).await;

    tracing::info!(
        "Exchanging code (performative) for client: {}, subject: {}",
        payload.client_id,
        context.claims.sub
    );

    tracing::debug!("Issuing tokens with audience: {}", aud);

    let claims = downstream::create_downstream_claims(
        state.settings.issuer.clone(),
        state.settings.token_expires_in,
        payload.client_id,
        aud,
        context.claims.sub,
        context.nonce,
        context.claims.other,
    );

    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("poltergeist".to_string());

    let token_string = encode(&header, &claims, &state.key_state.encoding_key).map_err(|e| {
        tracing::error!("Failed to encode JWT: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    let expires_in = state.settings.token_expires_in;

    tracing::info!("Tokens successfully issued for client");

    Ok(Json(TokenResponse {
        access_token: token_string.clone(),
        id_token: token_string,
        expires_in,
    }))
}

#[tracing::instrument(skip(state))]
async fn handle_client_credentials(
    state: Arc<AppState>,
    payload: TokenRequest,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    let client_secret = payload.client_secret.as_ref().ok_or_else(|| {
        tracing::warn!("Missing client_secret for client_credentials grant");
        (
            StatusCode::BAD_REQUEST,
            "missing client_secret for client_credentials grant".to_string(),
        )
    })?;

    tracing::info!(
        "Authenticating client_credentials for: {}",
        payload.client_id
    );

    // Find the client in the static configuration
    let client = state
        .settings
        .private_clients
        .iter()
        .find(|c| c.client_id == payload.client_id && c.client_secret == *client_secret)
        .ok_or_else(|| {
            tracing::warn!("Invalid client credentials for: {}", payload.client_id);
            (
                StatusCode::UNAUTHORIZED,
                "invalid client credentials".to_string(),
            )
        })?;

    let claims = downstream::create_downstream_claims_for_client_credentials(&state, client).await;

    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("poltergeist".to_string());

    let token_string = encode(&header, &claims, &state.key_state.encoding_key).map_err(|e| {
        tracing::error!("Failed to encode M2M JWT: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    tracing::info!("M2M tokens successfully issued for client");

    Ok(Json(TokenResponse {
        access_token: token_string.clone(),
        id_token: token_string, // For client_credentials, we often return the same token or similar
        expires_in: state.settings.token_expires_in,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::config::{PrivateClient, PublicClient, Settings};
    use crate::downstream::DownstreamClaims;
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
            token_expires_in: 3600,
            private_clients: vec![PrivateClient {
                client_id: "test-client".to_string(),
                client_secret: "test-secret".to_string(),
                audience: "aud".to_string(),
            }],
            public_clients: vec![],
            telemetry: Default::default(),
        };

        let state = Arc::new(AppState {
            settings,
            jwks_cache: Cache::builder().build(),
            auth_code_cache: Cache::builder().build(),
            key_state,
        });

        let payload = TokenRequest {
            grant_type: "client_credentials".to_string(),
            code: None,
            code_verifier: None,
            client_id: "test-client".to_string(),
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
            token_expires_in: 3600,
            private_clients: vec![PrivateClient {
                client_id: "test-client".to_string(),
                client_secret: "test-secret".to_string(),
                audience: "aud".to_string(),
            }],
            public_clients: vec![],
            telemetry: Default::default(),
        };

        let state = Arc::new(AppState {
            settings,
            jwks_cache: Cache::builder().build(),
            auth_code_cache: Cache::builder().build(),
            key_state,
        });

        let payload = TokenRequest {
            grant_type: "client_credentials".to_string(),
            code: None,
            code_verifier: None,
            client_id: "test-client".to_string(),
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
            token_expires_in: 3600,
            private_clients: vec![PrivateClient {
                client_id: "test-client".to_string(),
                client_secret: "test-secret".to_string(),
                audience: "custom-audience".to_string(),
            }],
            public_clients: vec![],
            telemetry: Default::default(),
        };

        let state = Arc::new(AppState {
            settings,
            jwks_cache: Cache::builder().build(),
            auth_code_cache: Cache::builder().build(),
            key_state,
        });

        let payload = TokenRequest {
            grant_type: "client_credentials".to_string(),
            code: None,
            code_verifier: None,
            client_id: "test-client".to_string(),
            client_secret: Some("test-secret".to_string()),
        };

        let Json(response) = handle_client_credentials(state, payload).await.unwrap();

        let token_data =
            jsonwebtoken::dangerous::insecure_decode::<DownstreamClaims>(&response.access_token)
                .unwrap();

        assert_eq!(token_data.claims.aud, "custom-audience");
    }

    #[tokio::test]
    async fn test_handle_authorization_code_success() {
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
            token_expires_in: 3600,
            private_clients: vec![],
            public_clients: vec![PublicClient {
                client_id: "web-app".to_string(),
                audience: "custom-app-aud".to_string(),
            }],
            telemetry: Default::default(),
        };

        let state = Arc::new(AppState {
            settings,
            jwks_cache: Cache::builder().build(),
            auth_code_cache: Cache::builder().build(),
            key_state,
        });

        // Mock upstream token
        let upstream_claims = crate::upstream::UpstreamClaims {
            sub: "test-user".to_string(),
            email: "test@example.com".to_string(),
            exp: 10000000000,
            other: HashMap::new(),
        };
        let context = crate::upstream::AuthorizationCodeContext {
            claims: upstream_claims,
            nonce: Some("test-nonce".to_string()),
        };
        let code = "any-code".to_string();
        state
            .auth_code_cache
            .insert(code.clone(), context)
            .await;

        let payload = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(code),
            code_verifier: None,
            client_id: "web-app".to_string(),
            client_secret: None,
        };

        let Json(response) = handle_authorization_code(state, payload).await.unwrap();

        let token_data =
            jsonwebtoken::dangerous::insecure_decode::<DownstreamClaims>(&response.access_token)
                .unwrap();

        assert_eq!(token_data.claims.aud, "custom-app-aud");
        assert_eq!(token_data.claims.sub, "test-user");
        assert_eq!(token_data.claims.nonce, Some("test-nonce".to_string()));
    }

    #[tokio::test]
    async fn test_handle_authorization_code_confidential_client_success() {
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
            token_expires_in: 3600,
            private_clients: vec![PrivateClient {
                client_id: "confidential-client".to_string(),
                client_secret: "top-secret".to_string(),
                audience: "confidential-aud".to_string(),
            }],
            public_clients: vec![],
            telemetry: Default::default(),
        };

        let state = Arc::new(AppState {
            settings,
            jwks_cache: Cache::builder().build(),
            auth_code_cache: Cache::builder().build(),
            key_state,
        });

        // 1. Put identity in cache
        let upstream_claims = crate::upstream::UpstreamClaims {
            sub: "confidential-user".to_string(),
            email: "confid@example.com".to_string(),
            exp: 10000000000,
            other: HashMap::new(),
        };
        let context = crate::upstream::AuthorizationCodeContext {
            claims: upstream_claims,
            nonce: None,
        };
        let code = "confidential-code".to_string();
        state
            .auth_code_cache
            .insert(code.clone(), context)
            .await;

        // 2. Call handler with code and secret
        let payload = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(code),
            code_verifier: None,
            client_id: "confidential-client".to_string(),
            client_secret: Some("top-secret".to_string()),
        };

        let Json(response) = handle_authorization_code(state, payload).await.unwrap();

        let token_data =
            jsonwebtoken::dangerous::insecure_decode::<DownstreamClaims>(&response.access_token)
                .unwrap();

        assert_eq!(token_data.claims.aud, "confidential-aud");
        assert_eq!(token_data.claims.sub, "confidential-user");
    }
}
