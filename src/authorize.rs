//! Logic for the `/authorize` endpoint.
//!
//! Handles the first step of the OAuth 2.0 authorization code flow.
//! It validates the upstream IDP's token (from the Authorization header)
//! and, if valid, issues a temporary authorization code.

use crate::{AppState, jwt::upstream, token::JsonOrForm};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Parameters for the authorization request.
#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
pub struct AuthorizeRequest {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    response_mode: Option<String>,
    scope: Option<String>,
    code_challenge: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
}

/// Handler for the `/authorize` endpoint via GET.
pub async fn authorize_get(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthorizeRequest>,
    headers: HeaderMap,
) -> impl IntoResponse {
    authorize_impl(state, params, headers).await
}

/// Handler for the `/authorize` endpoint via POST.
pub async fn authorize_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    JsonOrForm(params): JsonOrForm<AuthorizeRequest>,
) -> impl IntoResponse {
    authorize_impl(state, params, headers).await
}

/// Core logic for the `/authorize` endpoint.
///
/// 1.  Checks for an `Authorization: Bearer <token>` header.
/// 2.  If missing, redirects to the upstream OIDC provider.
/// 3.  If present, decodes (and optionally validates) the token to extract user identity.
/// 4.  Generates a random authorization code.
/// 5.  Redirects back to the `redirect_uri` with the code.
#[tracing::instrument(
    skip(state, headers, params),
    fields(
        client_id = params.client_id,
        redirect_uri = params.redirect_uri,
        response_type = params.response_type,
        response_mode = params.response_mode
    )
)]
async fn authorize_impl(
    state: Arc<AppState>,
    params: AuthorizeRequest,
    headers: HeaderMap,
) -> Response {
    tracing::info!(
        "Received authorization request for client: {}",
        params.client_id
    );

    // Validate client_id
    if !state
        .settings
        .public_clients
        .iter()
        .any(|c| c.client_id == params.client_id)
        && !state
            .settings
            .confidential_clients
            .iter()
            .any(|c| c.client_id == params.client_id)
    {
        tracing::warn!("Invalid client_id: {}", params.client_id);
        return (StatusCode::BAD_REQUEST, "Invalid client_id").into_response();
    }

    // Ensure the header is present and valid
    let identity = match upstream::get_upstream_identity(&state, &headers).await {
        Ok(id) => id,
        Err((status, msg)) => {
            tracing::warn!("Failed to get upstream identity: {} - {}", status, msg);
            return (StatusCode::BAD_REQUEST, format!("Authentication required: {}", msg)).into_response();
        }
    };

    let auth_code = generate_random_code();
    let context = upstream::AuthorizationCodeContext {
        claims: identity,
        nonce: params.nonce,
        scope: params.scope.clone(),
    };

    state
        .auth_code_cache
        .insert(auth_code.clone(), context)
        .await;

    tracing::info!("Issued authorization code for client: {}", params.client_id);

    // Handle Response Modes
    let state_param = params.state.unwrap_or_default();
    let mode = params.response_mode.as_deref().unwrap_or("query");

    match mode {
        "fragment" => {
            let mut redirect_url = format!("{}#code={}", params.redirect_uri, auth_code);
            if !state_param.is_empty() {
                redirect_url.push_str(&format!("&state={}", state_param));
            }
            Redirect::to(&redirect_url).into_response()
        }
        _ => {
            // Default "query"
            let mut redirect_url = format!("{}?code={}", params.redirect_uri, auth_code);
            if !state_param.is_empty() {
                redirect_url.push_str(&format!("&state={}", state_param));
            }
            Redirect::to(&redirect_url).into_response()
        }
    }
}

/// Generates a random 16-character alphanumeric string.
fn generate_random_code() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::{
        config::{self, PublicClient},
        jwks::{Jwk, Jwks},
        key,
        jwt::upstream::UpstreamClaims,
    };
    use axum::http::{StatusCode, header};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_authorize_success() {
        // 1. Setup Mock JWKS
        let mock_server = MockServer::start().await;

        let mut rng = rand::thread_rng();
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        // Prepare JWKS response
        let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: "test-kid".to_string(),
            n,
            e,
            alg: "RS256".to_string(),
            r#use: "sig".to_string(),
        };
        let jwks = Jwks { keys: vec![jwk] };

        Mock::given(method("GET"))
            .and(path("/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&mock_server)
            .await;

        // 2. Setup AppState
        let settings = config::Settings {
            issuer: "http://localhost:8080".to_string(),
            port: 8080,
            upstream_jwks_url: format!("{}/jwks.json", mock_server.uri()),
            validate_upstream_token: true,
            signing_key_path: "test/private_key.pem".to_string(),
            token_expires_in: 3600,
            confidential_clients: vec![],
            public_clients: vec![PublicClient {
                client_id: "client".to_string(),
                audience: "aud".to_string(),
            }],
            telemetry: Default::default(),
            ..config::Settings::default()
        };

        let app_private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let app_private_key_pem = app_private_key
            .to_pkcs8_pem(Default::default())
            .unwrap()
            .to_string();

        let state = Arc::new(AppState {
            settings,
            jwks_cache: moka::future::Cache::builder().build(),
            auth_code_cache: moka::future::Cache::builder().build(),
            key_state: key::KeyState::new(&app_private_key_pem),
        });

        // 3. Create Upstream Token
        let claims = UpstreamClaims {
            sub: "test-user".to_string(),
            email: "test@example.com".to_string(),
            exp: 10000000000, // far in the future
            other: HashMap::new(),
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-kid".to_string());

        let encoding_key =
            EncodingKey::from_rsa_der(private_key.to_pkcs1_der().unwrap().as_bytes());
        let token = encode(&header, &claims, &encoding_key).unwrap();

        // 4. Call Handler
        let params = AuthorizeRequest {
            client_id: "client".to_string(),
            redirect_uri: "http://client/cb".to_string(),
            response_type: "code".to_string(),
            response_mode: None,
            scope: Some("openid profile".to_string()),
            code_challenge: Some("challenge".to_string()),
            state: Some("test-state".to_string()),
            nonce: Some("test-nonce".to_string()),
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", token).parse().unwrap(),
        );

        let response = authorize_get(State(state.clone()), Query(params), headers)
            .await
            .into_response();

        // 5. Assertions
        assert_eq!(response.status(), StatusCode::SEE_OTHER);

        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.starts_with("http://client/cb?code="));
        assert!(location.contains("state=test-state"));
    }

    #[tokio::test]
    async fn test_authorize_fragment_mode() {
        let mut rng = rand::thread_rng();
        let app_private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let app_private_key_pem = app_private_key
            .to_pkcs8_pem(Default::default())
            .unwrap()
            .to_string();

        let settings = config::Settings {
            issuer: "http://localhost:8080".to_string(),
            port: 8080,
            upstream_jwks_url: "".to_string(),
            validate_upstream_token: false,
            signing_key_path: "test/private_key.pem".to_string(),
            token_expires_in: 3600,
            confidential_clients: vec![],
            public_clients: vec![PublicClient {
                client_id: "client".to_string(),
                audience: "aud".to_string(),
            }],
            telemetry: Default::default(),
            ..config::Settings::default()
        };

        let state = Arc::new(AppState {
            settings,
            jwks_cache: moka::future::Cache::builder().build(),
            auth_code_cache: moka::future::Cache::builder().build(),
            key_state: key::KeyState::new(&app_private_key_pem),
        });

        // Mock token
        let claims = UpstreamClaims {
            sub: "test".to_string(),
            email: "t@e.c".to_string(),
            exp: 9999999999,
            other: HashMap::new(),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("any".to_string());
        let encoding_key = EncodingKey::from_rsa_der(app_private_key.to_pkcs1_der().unwrap().as_bytes());
        let token = encode(&header, &claims, &encoding_key).unwrap();

        let params = AuthorizeRequest {
            client_id: "client".to_string(),
            redirect_uri: "http://client/cb".to_string(),
            response_type: "code".to_string(),
            response_mode: Some("fragment".to_string()),
            scope: None,
            code_challenge: None,
            state: Some("xyz".to_string()),
            nonce: None,
        };

        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, format!("Bearer {}", token).parse().unwrap());

        let response = authorize_get(State(state), Query(params), headers).await.into_response();
        
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("#code="));
        assert!(location.contains("state=xyz"));
    }

    #[tokio::test]
    async fn test_authorize_post_success() {
        // 1. Setup Mock JWKS
        let mock_server = MockServer::start().await;

        let mut rng = rand::thread_rng();
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: "test-kid".to_string(),
            n,
            e,
            alg: "RS256".to_string(),
            r#use: "sig".to_string(),
        };
        let jwks = Jwks { keys: vec![jwk] };

        Mock::given(method("GET"))
            .and(path("/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&mock_server)
            .await;

        // 2. Setup AppState
        let settings = config::Settings {
            issuer: "http://localhost:8080".to_string(),
            port: 8080,
            upstream_jwks_url: format!("{}/jwks.json", mock_server.uri()),
            validate_upstream_token: true,
            signing_key_path: "test/private_key.pem".to_string(),
            token_expires_in: 3600,
            confidential_clients: vec![],
            public_clients: vec![PublicClient {
                client_id: "client".to_string(),
                audience: "aud".to_string(),
            }],
            telemetry: Default::default(),
            ..config::Settings::default()
        };

        let app_private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let app_private_key_pem = app_private_key
            .to_pkcs8_pem(Default::default())
            .unwrap()
            .to_string();

        let state = Arc::new(AppState {
            settings,
            jwks_cache: moka::future::Cache::builder().build(),
            auth_code_cache: moka::future::Cache::builder().build(),
            key_state: key::KeyState::new(&app_private_key_pem),
        });

        // 3. Create Upstream Token
        let claims = UpstreamClaims {
            sub: "test-user".to_string(),
            email: "test@example.com".to_string(),
            exp: 10000000000,
            other: HashMap::new(),
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-kid".to_string());

        let encoding_key =
            EncodingKey::from_rsa_der(private_key.to_pkcs1_der().unwrap().as_bytes());
        let token = encode(&header, &claims, &encoding_key).unwrap();

        // 4. Call Handler via POST Form
        let params = AuthorizeRequest {
            client_id: "client".to_string(),
            redirect_uri: "http://client/cb".to_string(),
            response_type: "code".to_string(),
            response_mode: None,
            scope: None,
            code_challenge: Some("challenge".to_string()),
            state: None,
            nonce: None,
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", token).parse().unwrap(),
        );

        let response = authorize_post(State(state.clone()), headers, JsonOrForm(params))
            .await
            .into_response();

        // 5. Assertions
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.starts_with("http://client/cb?code="));
    }

    #[tokio::test]
    async fn test_authorize_post_json_success() {
         // 1. Setup Mock JWKS
        let mock_server = MockServer::start().await;

        let mut rng = rand::thread_rng();
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        let jwk = Jwk {
            kty: "RSA".to_string(),
            kid: "test-kid".to_string(),
            n,
            e,
            alg: "RS256".to_string(),
            r#use: "sig".to_string(),
        };
        let jwks = Jwks { keys: vec![jwk] };

        Mock::given(method("GET"))
            .and(path("/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&mock_server)
            .await;

        // 2. Setup AppState
        let settings = config::Settings {
            issuer: "http://localhost:8080".to_string(),
            port: 8080,
            upstream_jwks_url: format!("{}/jwks.json", mock_server.uri()),
            validate_upstream_token: true,
            signing_key_path: "test/private_key.pem".to_string(),
            token_expires_in: 3600,
            confidential_clients: vec![],
            public_clients: vec![PublicClient {
                client_id: "client".to_string(),
                audience: "aud".to_string(),
            }],
            telemetry: Default::default(),
            ..config::Settings::default()
        };

        let app_private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let app_private_key_pem = app_private_key
            .to_pkcs8_pem(Default::default())
            .unwrap()
            .to_string();

        let state = Arc::new(AppState {
            settings,
            jwks_cache: moka::future::Cache::builder().build(),
            auth_code_cache: moka::future::Cache::builder().build(),
            key_state: key::KeyState::new(&app_private_key_pem),
        });

        // 3. Create Upstream Token
        let claims = UpstreamClaims {
            sub: "test-user".to_string(),
            email: "test@example.com".to_string(),
            exp: 10000000000,
            other: HashMap::new(),
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-kid".to_string());

        let encoding_key =
            EncodingKey::from_rsa_der(private_key.to_pkcs1_der().unwrap().as_bytes());
        let token = encode(&header, &claims, &encoding_key).unwrap();

        // 4. Call Handler via POST (Simulating JSON by wrapping in JsonOrForm)
        let params = AuthorizeRequest {
            client_id: "client".to_string(),
            redirect_uri: "http://client/cb".to_string(),
            response_type: "code".to_string(),
            response_mode: None,
            scope: None,
            code_challenge: Some("challenge".to_string()),
            state: None,
            nonce: None,
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", token).parse().unwrap(),
        );
        // Note: Content-Type header isn't checked by the handler function itself,
        // it's checked by the Extractor during routing.
        // But we are testing the handler logic here.

        let response = authorize_post(State(state.clone()), headers, JsonOrForm(params))
            .await
            .into_response();

        // 5. Assertions
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.starts_with("http://client/cb?code="));
    }

    #[tokio::test]
    async fn test_authorize_missing_header() {
        let mut rng = rand::thread_rng();
        let app_private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let app_private_key_pem = app_private_key
            .to_pkcs8_pem(Default::default())
            .unwrap()
            .to_string();

        let settings = config::Settings {
            issuer: "http://localhost:8080".to_string(),
            port: 8080,
            upstream_jwks_url: "".to_string(),
            validate_upstream_token: true,
            signing_key_path: "test/private_key.pem".to_string(),
            token_expires_in: 3600,
            confidential_clients: vec![],
            public_clients: vec![PublicClient {
                client_id: "client".to_string(),
                audience: "aud".to_string(),
            }],
            telemetry: Default::default(),
            ..config::Settings::default()
        };

        let state = Arc::new(AppState {
            settings,
            jwks_cache: moka::future::Cache::builder().build(),
            auth_code_cache: moka::future::Cache::builder().build(),
            key_state: key::KeyState::new(&app_private_key_pem),
        });

        let params = AuthorizeRequest {
            client_id: "client".to_string(),
            redirect_uri: "http://client/cb".to_string(),
            response_type: "code".to_string(),
            response_mode: None,
            scope: None,
            code_challenge: Some("challenge".to_string()),
            state: None,
            nonce: None,
        };

        let headers = HeaderMap::new(); // No Authorization header

        let response = authorize_get(State(state.clone()), Query(params), headers)
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 1024).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("Authentication required"));
    }

    #[tokio::test]
    async fn test_authorize_confidential_client_success() {
        let mut rng = rand::thread_rng();
        let app_private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let app_private_key_pem = app_private_key
            .to_pkcs8_pem(Default::default())
            .unwrap()
            .to_string();

        let settings = config::Settings {
            issuer: "http://localhost:8080".to_string(),
            port: 8080,
            upstream_jwks_url: "".to_string(),
            validate_upstream_token: false, // Skip validation for simplicity
            signing_key_path: "test/private_key.pem".to_string(),
            token_expires_in: 3600,
            confidential_clients: vec![config::ConfidentialClient {
                client_id: "confidential-client".to_string(),
                client_secret: Some("secret".to_string()),
                client_secret_env: None,
                audience: "aud".to_string(),
            }],
            public_clients: vec![],
            telemetry: Default::default(),
            ..config::Settings::default()
        };

        let state = Arc::new(AppState {
            settings,
            jwks_cache: moka::future::Cache::builder().build(),
            auth_code_cache: moka::future::Cache::builder().build(),
            key_state: key::KeyState::new(&app_private_key_pem),
        });

        // Mock Upstream Token (since we disabled validation, signature doesn't matter much but we need claims)
        let claims = UpstreamClaims {
            sub: "test-user".to_string(),
            email: "test@example.com".to_string(),
            exp: 10000000000,
            other: HashMap::new(),
        };
        // We still need a valid structure even if signature isn't validated by logic, 
        // but wait, `upstream::get_upstream_identity` validates signature if `validate_upstream_token` is true.
        // If false, it just decodes.
        // We need to provide a somewhat valid JWT structure.
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("any".to_string());
        // We can sign with *any* key since validation is off
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let encoding_key = EncodingKey::from_rsa_der(private_key.to_pkcs1_der().unwrap().as_bytes());
        let token = encode(&header, &claims, &encoding_key).unwrap();

        let params = AuthorizeRequest {
            client_id: "confidential-client".to_string(),
            redirect_uri: "http://confidential/cb".to_string(),
            response_type: "code".to_string(),
            response_mode: None,
            scope: None,
            code_challenge: Some("challenge".to_string()),
            state: None,
            nonce: None,
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", token).parse().unwrap(),
        );

        let response = authorize_get(State(state.clone()), Query(params), headers)
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.starts_with("http://confidential/cb?code="));
    }
}
