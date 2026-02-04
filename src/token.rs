//! Logic for the `/token` endpoint.
//!
//! Handles the exchange of authorization codes (or client credentials) for access and ID tokens.

use crate::AppState;
use crate::jwt::downstream;
use axum::{Form, Json};
use axum::extract::{FromRequest, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use jsonwebtoken::{Header, encode};
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
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

/// Helper extractor for handling both JSON and Form requests.
pub struct JsonOrForm<T>(pub T);

impl<S, T> FromRequest<S> for JsonOrForm<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send + 'static,
    Json<T>: FromRequest<S, Rejection = axum::extract::rejection::JsonRejection>,
    Form<T>: FromRequest<S, Rejection = axum::extract::rejection::FormRejection>,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let content_type = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");

        if content_type.starts_with("application/x-www-form-urlencoded") {
            let Form(payload) = Form::<T>::from_request(req, state)
                .await
                .map_err(|e| e.into_response())?;
            Ok(JsonOrForm(payload))
        } else {
            let Json(payload) = Json::<T>::from_request(req, state)
                .await
                .map_err(|e| e.into_response())?;
            Ok(JsonOrForm(payload))
        }
    }
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
    skip(state, headers, payload),
    fields(
        grant_type = payload.grant_type,
        client_id = payload.client_id,
        code = payload.code
    )
)]
pub async fn token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    JsonOrForm(mut payload): JsonOrForm<TokenRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    tracing::info!("Received token request: grant_type={}", payload.grant_type);

    // Handle Basic Authentication
    // Only check header if client_secret is NOT provided in the payload.
    // This enforces precedence and avoids parsing headers unnecessarily or mixing credentials.
    if payload.client_secret.is_none() {
        if let Some(auth_value) = headers.get(AUTHORIZATION) {
            if let Ok(auth_str) = auth_value.to_str() {
                if auth_str.starts_with("Basic ") {
                    let credentials = auth_str.trim_start_matches("Basic ");
                    if let Ok(decoded) = STANDARD.decode(credentials) {
                        if let Ok(cred_str) = String::from_utf8(decoded) {
                            if let Some((id, secret)) = cred_str.split_once(':') {
                                // If client_id is missing in body, use from header
                                if payload.client_id.is_none() {
                                    payload.client_id = Some(id.to_string());
                                }
                                payload.client_secret = Some(secret.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // Ensure client_id is present
    if payload.client_id.is_none() {
        return Err((StatusCode::BAD_REQUEST, "missing client_id".to_string()));
    }

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
    let client_id = payload.client_id.as_ref().unwrap();

    // Try to find as public client first
    let public_client = state
        .settings
        .public_clients
        .iter()
        .find(|c| c.client_id == *client_id);

    let aud = if let Some(c) = public_client {
        c.audience.clone()
    } else {
        // Try confidential clients
        let confidential_client = state
            .settings
            .confidential_clients
            .iter()
            .find(|c| c.client_id == *client_id)
            .ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("{} is not a valid client_id", client_id),
                )
            })?;

        let effective_secret = confidential_client.get_secret();
        // For confidential clients, we MUST have a secret and it MUST match
        let secret = payload.client_secret.as_deref().ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "client_secret required for confidential client".to_string(),
            )
        })?;

        if effective_secret.as_deref() != Some(secret) {
            return Err((
                StatusCode::UNAUTHORIZED,
                "invalid client secret".to_string(),
            ));
        }

        confidential_client.audience.clone()
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
        client_id,
        context.claims.sub
    );

    tracing::debug!("Issuing tokens with audience: {}", aud);

    let claims = downstream::create_downstream_claims(
        state.settings.issuer.clone(),
        state.settings.token_expires_in,
        client_id.clone(),
        aud,
        context.claims.sub,
        context.nonce,
        context.scope,
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
    let client_id = payload.client_id.as_ref().unwrap();
    let client_secret = payload.client_secret.as_ref().ok_or_else(|| {
        tracing::warn!("Missing client_secret for client_credentials grant");
        (
            StatusCode::BAD_REQUEST,
            "missing client_secret for client_credentials grant".to_string(),
        )
    })?;

    tracing::info!(
        "Authenticating client_credentials for: {}",
        client_id
    );

    // Find the client in the static configuration
    let client = state
        .settings
        .confidential_clients
        .iter()
        .find(|c| {
            c.client_id == *client_id
                && c.get_secret().as_deref() == Some(client_secret.as_str())
        })
        .ok_or_else(|| {
            tracing::warn!("Invalid client credentials for: {}", client_id);
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
    use crate::config::{ConfidentialClient, PublicClient, Settings};
    use crate::jwt::downstream::DownstreamClaims;
    use crate::key::KeyState;
    use moka::future::Cache;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_handle_client_credentials_success() {
        let private_key_pem = std::fs::read_to_string("test/private_key.pem").unwrap();
        let key_state = KeyState::new(&private_key_pem);

        let settings = Settings {
            issuer: "http://localhost:8080".to_string(),
            port: 8080,
            upstream_oidc_url: "http://upstream".to_string(),
            upstream_jwks_url: "http://upstream/jwks".to_string(),
            validate_upstream_token: false,
            signing_key_path: "test/private_key.pem".to_string(),
            token_expires_in: 3600,
            confidential_clients: vec![ConfidentialClient {
                client_id: "test-client".to_string(),
                client_secret: Some("test-secret".to_string()),
                client_secret_env: None,
                audience: "aud".to_string(),
            }],
            public_clients: vec![],
            telemetry: Default::default(),
            ..Settings::default()
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
            port: 8080,
            upstream_oidc_url: "http://upstream".to_string(),
            upstream_jwks_url: "http://upstream/jwks".to_string(),
            validate_upstream_token: false,
            signing_key_path: "test/private_key.pem".to_string(),
            token_expires_in: 3600,
            confidential_clients: vec![ConfidentialClient {
                client_id: "test-client".to_string(),
                client_secret: Some("test-secret".to_string()),
                client_secret_env: None,
                audience: "aud".to_string(),
            }],
            public_clients: vec![],
            telemetry: Default::default(),
            ..Settings::default()
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
            port: 8080,
            upstream_oidc_url: "http://upstream".to_string(),
            upstream_jwks_url: "http://upstream/jwks".to_string(),
            validate_upstream_token: false,
            signing_key_path: "test/private_key.pem".to_string(),
            token_expires_in: 3600,
            confidential_clients: vec![ConfidentialClient {
                client_id: "test-client".to_string(),
                client_secret: Some("test-secret".to_string()),
                client_secret_env: None,
                audience: "custom-audience".to_string(),
            }],
            public_clients: vec![],
            telemetry: Default::default(),
            ..Settings::default()
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
            port: 8080,
            upstream_oidc_url: "http://upstream".to_string(),
            upstream_jwks_url: "http://upstream/jwks".to_string(),
            validate_upstream_token: false,
            signing_key_path: "test/private_key.pem".to_string(),
            token_expires_in: 3600,
            confidential_clients: vec![],
            public_clients: vec![PublicClient {
                client_id: "web-app".to_string(),
                audience: "custom-app-aud".to_string(),
            }],
            telemetry: Default::default(),
            ..Settings::default()
        };

        let state = Arc::new(AppState {
            settings,
            jwks_cache: Cache::builder().build(),
            auth_code_cache: Cache::builder().build(),
            key_state,
        });

        // Mock upstream token
        let upstream_claims = crate::jwt::upstream::UpstreamClaims {
            sub: "test-user".to_string(),
            email: "test@example.com".to_string(),
            exp: 10000000000,
            other: HashMap::new(),
        };
        let context = crate::jwt::upstream::AuthorizationCodeContext {
            claims: upstream_claims,
            nonce: Some("test-nonce".to_string()),
            scope: Some("openid profile".to_string()),
        };
        let code = "any-code".to_string();
        state.auth_code_cache.insert(code.clone(), context).await;

        let payload = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(code),
            code_verifier: None,
            client_id: Some("web-app".to_string()),
            client_secret: None,
        };

        let Json(response) = handle_authorization_code(state, payload).await.unwrap();

        let token_data =
            jsonwebtoken::dangerous::insecure_decode::<DownstreamClaims>(&response.access_token)
                .unwrap();

        assert_eq!(token_data.claims.aud, "custom-app-aud");
        assert_eq!(token_data.claims.sub, "test-user");
        assert_eq!(token_data.claims.nonce, Some("test-nonce".to_string()));
        assert_eq!(token_data.claims.scope, Some("openid profile".to_string()));
    }

    #[tokio::test]
    async fn test_handle_authorization_code_confidential_client_success() {
        let private_key_pem = std::fs::read_to_string("test/private_key.pem").unwrap();
        let key_state = KeyState::new(&private_key_pem);

        let settings = Settings {
            issuer: "http://localhost:8080".to_string(),
            port: 8080,
            upstream_oidc_url: "http://upstream".to_string(),
            upstream_jwks_url: "http://upstream/jwks".to_string(),
            validate_upstream_token: false,
            signing_key_path: "test/private_key.pem".to_string(),
            token_expires_in: 3600,
            confidential_clients: vec![ConfidentialClient {
                client_id: "confidential-client".to_string(),
                client_secret: Some("top-secret".to_string()),
                client_secret_env: None,
                audience: "confidential-aud".to_string(),
            }],
            public_clients: vec![],
            telemetry: Default::default(),
            ..Settings::default()
        };

        let state = Arc::new(AppState {
            settings,
            jwks_cache: Cache::builder().build(),
            auth_code_cache: Cache::builder().build(),
            key_state,
        });

        // 1. Put identity in cache
        let upstream_claims = crate::jwt::upstream::UpstreamClaims {
            sub: "confidential-user".to_string(),
            email: "confid@example.com".to_string(),
            exp: 10000000000,
            other: HashMap::new(),
        };
        let context = crate::jwt::upstream::AuthorizationCodeContext {
            claims: upstream_claims,
            nonce: None,
            scope: None,
        };
        let code = "confidential-code".to_string();
        state.auth_code_cache.insert(code.clone(), context).await;

        // 2. Call handler with code and secret
        let payload = TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(code),
            code_verifier: None,
            client_id: Some("confidential-client".to_string()),
            client_secret: Some("top-secret".to_string()),
        };

        let Json(response) = handle_authorization_code(state, payload).await.unwrap();

        let token_data =
            jsonwebtoken::dangerous::insecure_decode::<DownstreamClaims>(&response.access_token)
                .unwrap();

        assert_eq!(token_data.claims.aud, "confidential-aud");
        assert_eq!(token_data.claims.sub, "confidential-user");
    }

    #[tokio::test]
    async fn test_handle_client_credentials_env_secret() {
        let env_var_name = "TEST_CLIENT_SECRET_ENV_VAR";
        unsafe { std::env::set_var(env_var_name, "env-secret-value") };

        let private_key_pem = std::fs::read_to_string("test/private_key.pem").unwrap();
        let key_state = KeyState::new(&private_key_pem);

        let settings = Settings {
            issuer: "http://localhost:8080".to_string(),
            port: 8080,
            upstream_oidc_url: "http://upstream".to_string(),
            upstream_jwks_url: "http://upstream/jwks".to_string(),
            validate_upstream_token: false,
            signing_key_path: "test/private_key.pem".to_string(),
            token_expires_in: 3600,
            confidential_clients: vec![ConfidentialClient {
                client_id: "env-client".to_string(),
                client_secret: None,
                client_secret_env: Some(env_var_name.to_string()),
                audience: "aud".to_string(),
            }],
            public_clients: vec![],
            telemetry: Default::default(),
            ..Settings::default()
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
            client_id: Some("env-client".to_string()),
            client_secret: Some("env-secret-value".to_string()),
        };

        let Json(response) = handle_client_credentials(state, payload).await.unwrap();
        assert!(!response.access_token.is_empty());
        
        unsafe { std::env::remove_var(env_var_name) };
    }

    #[tokio::test]
    async fn test_json_or_form_extractor() {
        use axum::extract::{FromRequest, Request};
        use axum::http::header::CONTENT_TYPE;
        use axum::body::Body;
        use axum::http::Method;

        // Test JSON
        let req = Request::builder()
            .method(Method::POST)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"client_id":"test","grant_type":"client_credentials"}"#))
            .unwrap();
        
        let JsonOrForm(payload) = JsonOrForm::<TokenRequest>::from_request(req, &()).await.unwrap();
        assert_eq!(payload.client_id, Some("test".to_string()));
        assert_eq!(payload.grant_type, "client_credentials");

        // Test Form
        let req = Request::builder()
            .method(Method::POST)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("client_id=test&grant_type=client_credentials"))
            .unwrap();
        
        let JsonOrForm(payload) = JsonOrForm::<TokenRequest>::from_request(req, &()).await.unwrap();
        assert_eq!(payload.client_id, Some("test".to_string()));
        assert_eq!(payload.grant_type, "client_credentials");
    }

    #[tokio::test]
    async fn test_token_basic_auth() {
        let private_key_pem = std::fs::read_to_string("test/private_key.pem").unwrap();
        let key_state = KeyState::new(&private_key_pem);

        let settings = Settings {
            issuer: "http://localhost:8080".to_string(),
            port: 8080,
            upstream_oidc_url: "http://upstream".to_string(),
            upstream_jwks_url: "http://upstream/jwks".to_string(),
            validate_upstream_token: false,
            signing_key_path: "test/private_key.pem".to_string(),
            token_expires_in: 3600,
            confidential_clients: vec![ConfidentialClient {
                client_id: "basic-client".to_string(),
                client_secret: Some("basic-secret".to_string()),
                client_secret_env: None,
                audience: "aud".to_string(),
            }],
            public_clients: vec![],
            telemetry: Default::default(),
            ..Settings::default()
        };

        let state = Arc::new(AppState {
            settings,
            jwks_cache: Cache::builder().build(),
            auth_code_cache: Cache::builder().build(),
            key_state,
        });

        // Basic Auth encoded "basic-client:basic-secret"
        let credentials = base64::engine::general_purpose::STANDARD.encode("basic-client:basic-secret");
        
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            format!("Basic {}", credentials).parse().unwrap(),
        );

        let payload = TokenRequest {
            grant_type: "client_credentials".to_string(),
            code: None,
            code_verifier: None,
            client_id: None, // Missing in body, should take from header
            client_secret: None, // Missing in body, should take from header
        };

        let Json(response) = token(State(state), headers, JsonOrForm(payload)).await.unwrap();
        assert!(!response.access_token.is_empty());
    }
}
