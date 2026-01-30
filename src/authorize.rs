//! Logic for the `/authorize` endpoint.
//!
//! Handles the first step of the OAuth 2.0 authorization code flow.
//! It validates the upstream IDP's token (from the Authorization header)
//! and, if valid, issues a temporary authorization code.

use crate::{AppState, upstream};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
};
use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};
use serde::Deserialize;
use std::sync::Arc;

/// Parameters for the authorization request.
#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct AuthorizeRequest {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    code_challenge: String,
    // we can ignore state and other params for now
}

/// Handler for the `/authorize` endpoint.
///
/// 1.  Checks for an `Authorization: Bearer <token>` header.
/// 2.  If missing, redirects to the upstream OIDC provider.
/// 3.  If present, decodes (and optionally validates) the token to extract user identity.
/// 4.  Generates a random authorization code (dummy).
/// 5.  Redirects back to the `redirect_uri` with the code.
#[tracing::instrument(skip(state, headers))]
pub async fn authorize(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthorizeRequest>,
    headers: HeaderMap,
) -> impl IntoResponse {
    tracing::info!(
        audit = true,
        "Received authorization request for client: {}",
        params.client_id
    );

    // Validate client_id
    if !state
        .settings
        .public_clients
        .iter()
        .any(|c| c.client_id == params.client_id)
    {
        tracing::warn!(
            audit = true,
            "Invalid client_id: {}",
            params.client_id
        );
        return (StatusCode::BAD_REQUEST, "Invalid client_id").into_response();
    }

    // Ensure the header is present and valid
    let identity = match upstream::get_upstream_identity(&state, &headers).await {
        Ok(id) => id,
        Err((_, _)) => {
            tracing::info!(
                audit = true,
                "No valid Authorization header found, redirecting to upstream IDP"
            );
            return Redirect::to(&state.settings.upstream_oidc_url).into_response();
        }
    };

    let auth_code = generate_random_code();
    state.auth_code_cache.insert(auth_code.clone(), identity).await;

    tracing::info!(
        audit = true,
        "Issued dummy authorization code for client: {}",
        params.client_id
    );
    let redirect_url = format!("{}?code={}", params.redirect_uri, auth_code);
    Redirect::to(&redirect_url).into_response()
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
    use crate::{
        config::{self, PublicClient},
        jwks::{Jwk, Jwks},
        key,
        upstream::UpstreamClaims,
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
            grant_types_supported: vec![],
            port: 8080,
            upstream_oidc_url: "http://upstream".to_string(),
            upstream_jwks_url: format!("{}/jwks.json", mock_server.uri()),
            validate_upstream_token: true,
            private_key_path: "test/private_key.pem".to_string(),
            token_expires_in: 3600,
            private_clients: vec![],
            public_clients: vec![PublicClient {
                client_id: "client".to_string(),
                audience: "aud".to_string(),
            }],
            telemetry: Default::default(),
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
            code_challenge: "challenge".to_string(),
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", token).parse().unwrap(),
        );

        let response = authorize(State(state.clone()), Query(params), headers)
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
            grant_types_supported: vec![],
            port: 8080,
            upstream_oidc_url: "http://upstream-login".to_string(),
            upstream_jwks_url: "".to_string(),
            validate_upstream_token: true,
            private_key_path: "test/private_key.pem".to_string(),
            token_expires_in: 3600,
            private_clients: vec![],
            public_clients: vec![PublicClient {
                client_id: "client".to_string(),
                audience: "aud".to_string(),
            }],
            telemetry: Default::default(),
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
            code_challenge: "challenge".to_string(),
        };

        let headers = HeaderMap::new(); // No Authorization header

        let response = authorize(State(state.clone()), Query(params), headers)
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response
                .headers()
                .get("location")
                .unwrap()
                .to_str()
                .unwrap(),
            "http://upstream-login"
        );
    }
}
