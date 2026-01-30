//! Logic for the `/token` endpoint.
//!
//! Handles the exchange of authorization codes (or client credentials) for access and ID tokens.

use crate::config::ClientType;
use crate::minted::DownstreamClaims;
use crate::{AppState, upstream};
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use jsonwebtoken::{Header, encode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Parameters for the token exchange request.
#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct TokenRequest {
    /// The grant type (e.g., "authorization_code" or "client_credentials").
    grant_type: String,
    /// The authorization code received from the `/authorize` endpoint.
    code: Option<String>,
    /// PKCE code verifier (currently ignored but part of the spec).
    code_verifier: Option<String>,
    /// Client identifier.
    pub client_id: Option<String>,
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
/// Handles both `authorization_code` and `client_credentials` grant types.
#[tracing::instrument(skip(state, headers))]
pub async fn token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    tracing::info!(
        audit = true,
        "Received token request: grant_type={}",
        payload.grant_type
    );
    match payload.grant_type.as_str() {
        "client_credentials" => handle_client_credentials(state, payload).await,
        "authorization_code" => handle_authorization_code(state, headers, payload).await,
        _ => {
            tracing::warn!("Unsupported grant type: {}", payload.grant_type);
            Err((
                StatusCode::BAD_REQUEST,
                format!("unsupported_grant_type: {}", payload.grant_type),
            ))
        }
    }
}

#[tracing::instrument(skip(state, headers))]
async fn handle_authorization_code(
    state: Arc<AppState>,
    headers: HeaderMap,
    payload: TokenRequest,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    // First ensure we're using a valid client

    let client_id = payload
        .client_id
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "no client_id provided".to_string()))?;

    let client = state
        .settings
        .public_clients
        .iter()
        .find(|c| c.client_id == client_id)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("{} is not a valid client_id", client_id),
            )
        })?;

    // We ignore the code parameter because this is a "performative" shim.
    // The actual identity comes from the Authorization header injected by the gateway.
    let user_identity = upstream::get_upstream_identity(&state, &headers).await?;

    tracing::info!(
        audit = true,
        "Exchanging code (performative) for client: {}, subject: {}",
        client_id,
        user_identity.sub
    );

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires_in = state.settings.token_expires_in;

    let aud = client.audience.clone();

    tracing::debug!("Issuing tokens with audience: {}", aud);

    let claims = DownstreamClaims {
        sub: user_identity.sub.clone(),
        aud: aud.to_string(),
        client_id,
        iss: state.settings.issuer.clone(),
        iat: now,
        exp: now + expires_in,
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

#[tracing::instrument(skip(state))]
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

    tracing::info!(
        audit = true,
        "Authenticating client_credentials for: {}",
        client_id
    );

    // Find the client in the static configuration
    let client = state
        .settings
        .private_clients
        .iter()
        .find(|c| c.client_id == client_id && c.client_secret == client_secret)
        .ok_or_else(|| {
            tracing::warn!(
                audit = true,
                "Invalid client credentials for: {}",
                client_id
            );
            (
                StatusCode::UNAUTHORIZED,
                "invalid client credentials".to_string(),
            )
        })?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires_in = state.settings.token_expires_in;

    let aud = client.audience.clone();

    tracing::debug!("Issuing M2M tokens with audience: {}", aud);

    let claims = DownstreamClaims {
        sub: client.client_id.clone(),
        aud,
        client_id,
        iss: state.settings.issuer.clone(),
        iat: now,
        exp: now + expires_in,
    };

    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("poltergeist".to_string());

    let token_string = encode(&header, &claims, &state.key_state.encoding_key).map_err(|e| {
        tracing::error!("Failed to encode M2M JWT: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    tracing::info!(audit = true, "M2M tokens successfully issued for client");

    Ok(Json(TokenResponse {
        access_token: token_string.clone(),
        id_token: token_string, // For client_credentials, we often return the same token or similar
        expires_in,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClientType, PrivateClient, PublicClient, Settings};
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
        };

        let state = Arc::new(AppState {
            settings,
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
            token_expires_in: 3600,
            private_clients: vec![PrivateClient {
                client_id: "test-client".to_string(),
                client_secret: "test-secret".to_string(),
                audience: "aud".to_string(),
            }],
            public_clients: vec![],
        };

        let state = Arc::new(AppState {
            settings,
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
            token_expires_in: 3600,
            private_clients: vec![PrivateClient {
                client_id: "test-client".to_string(),
                client_secret: "test-secret".to_string(),
                audience: "custom-audience".to_string(),
            }],
            public_clients: vec![],
        };

        let state = Arc::new(AppState {
            settings,
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
        };

        let state = Arc::new(AppState {
            settings,
            jwks_cache: Cache::builder().build(),
            key_state,
        });

        // Mock upstream token
        let upstream_claims = crate::upstream::UpstreamClaims {
            sub: "test-user".to_string(),
            email: "test@example.com".to_string(),
        };
        let upstream_token = jsonwebtoken::encode(
            &Header::default(),
            &upstream_claims,
            &jsonwebtoken::EncodingKey::from_secret("secret".as_ref()),
        )
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", upstream_token).parse().unwrap(),
        );

        let payload = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some("any-code".to_string()),
            code_verifier: None,
            client_id: Some("web-app".to_string()),
            client_secret: None,
        };

        let Json(response) = handle_authorization_code(state, headers, payload)
            .await
            .unwrap();

        let token_data =
            jsonwebtoken::dangerous::insecure_decode::<DownstreamClaims>(&response.access_token)
                .unwrap();

        assert_eq!(token_data.claims.aud, "custom-app-aud");
        assert_eq!(token_data.claims.sub, "test-user");
    }
}
