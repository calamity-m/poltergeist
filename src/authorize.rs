//! Logic for the `/authorize` endpoint.
//!
//! Handles the first step of the OAuth 2.0 authorization code flow.
//! It validates the upstream IDP's token (from the Authorization header)
//! and, if valid, issues a temporary authorization code.

use crate::{jwks::Jwks, AppState, UserIdentity};
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
};
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Parameters for the authorization request.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct AuthorizeRequest {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    code_challenge: String,
    // we can ignore state and other params for now
}

/// Claims expected in the upstream OIDC token.
#[derive(Debug, Deserialize, Serialize)]
struct UpstreamClaims {
    sub: String,
    email: String,
    groups: Vec<String>,
    exp: u64,
}

/// Handler for the `/authorize` endpoint.
///
/// 1.  Checks for an `Authorization: Bearer <token>` header.
/// 2.  If missing, redirects to the upstream OIDC provider.
/// 3.  If present, decodes (and optionally validates) the token to extract user identity.
/// 4.  Generates a random authorization code.
/// 5.  Stores the code mapped to the user identity in the cache.
/// 6.  Redirects back to the `redirect_uri` with the code.
pub async fn authorize(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthorizeRequest>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let upstream_token = match headers
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "))
    {
        Some(token) => token,
        None => {
            return Redirect::to(&state.settings.upstream_oidc_url).into_response();
        }
    };

    let mut user_identity = if state.settings.validate_upstream_token {
        match decode_token_with_validation(
            &state,
            upstream_token,
            &state.settings.upstream_jwks_url,
        )
        .await
        {
            Ok(identity) => identity,
            Err(e) => {
                tracing::error!("Failed to validate upstream token: {}", e);
                return (StatusCode::UNAUTHORIZED, "Invalid upstream token").into_response();
            }
        }
    } else {
        match decode_token_without_validation(upstream_token) {
            Ok(identity) => identity,
            Err(e) => {
                tracing::error!("Failed to decode upstream token: {}", e);
                return (StatusCode::BAD_REQUEST, "Invalid upstream token").into_response();
            }
        }
    };

    user_identity.client_id = params.client_id.clone();

    let auth_code = generate_random_code();
    state
        .auth_code_cache
        .insert(auth_code.clone(), user_identity)
        .await;

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

/// Decodes and validates a JWT against a remote JWKS.
///
/// Fetches the JWKS from `jwks_url` (caching it) and verifies the signature.
async fn decode_token_with_validation(
    state: &Arc<AppState>,
    token: &str,
    jwks_url: &str,
) -> Result<UserIdentity, anyhow::Error> {
    let header = decode_header(token)?;
    let kid = header.kid.ok_or_else(|| anyhow::anyhow!("Missing kid"))?;

    // Fetch JWKS, using the cache if available.
    let jwks: Arc<Jwks> = state
        .jwks_cache
        .try_get_with(jwks_url.to_string(), async {
            let jwks: Jwks = reqwest::get(jwks_url).await?.json().await?;
            Ok::<_, anyhow::Error>(jwks)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch or cache JWKS: {}", e))?
        .into();

    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| anyhow::anyhow!("JWK not found"))?;

    let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)?;
    let mut validation = Validation::new(header.alg);
    validation.validate_exp = true;
    let decoded = decode::<UpstreamClaims>(token, &decoding_key, &validation)?;

    Ok(UserIdentity {
        sub: decoded.claims.sub,
        email: decoded.claims.email,
        groups: decoded.claims.groups,
        client_id: "".to_string(),
    })
}

/// Decodes a JWT without validating the signature.
///
/// **WARNING:** This is insecure and should only be used if the token source is trusted
/// via other means (e.g., internal network, mTLS).
fn decode_token_without_validation(token: &str) -> Result<UserIdentity, anyhow::Error> {
    let decoded = jsonwebtoken::dangerous::insecure_decode::<UpstreamClaims>(token)?;
    Ok(UserIdentity {
        sub: decoded.claims.sub,
        email: decoded.claims.email,
        groups: decoded.claims.groups,
        client_id: "".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config, key, jwks::{Jwk, Jwks}};
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path};
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::traits::PublicKeyParts;
    use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

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
            clients: vec![],
        };

        let app_private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let app_private_key_pem = app_private_key.to_pkcs8_pem(Default::default()).unwrap().to_string();
        
        let state = Arc::new(AppState {
            settings,
            auth_code_cache: moka::future::Cache::builder().build(),
            jwks_cache: moka::future::Cache::builder().build(),
            key_state: key::KeyState::new(&app_private_key_pem),
        });

        // 3. Create Upstream Token
        let claims = UpstreamClaims {
            sub: "test-user".to_string(),
            email: "test@example.com".to_string(),
            groups: vec!["admin".to_string()],
            exp: 10000000000, // Way in the future
        };
        
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-kid".to_string());
        
        let encoding_key = EncodingKey::from_rsa_der(private_key.to_pkcs1_der().unwrap().as_bytes());
        let token = encode(&header, &claims, &encoding_key).unwrap();

        // 4. Call Handler
        let params = AuthorizeRequest {
            client_id: "client".to_string(),
            redirect_uri: "http://client/cb".to_string(),
            response_type: "code".to_string(),
            code_challenge: "challenge".to_string(),
        };
        
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, format!("Bearer {}", token).parse().unwrap());

        let response = authorize(State(state.clone()), Query(params), headers).await.into_response();

        // 5. Assertions
        assert_eq!(response.status(), StatusCode::SEE_OTHER); 
        
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with("http://client/cb?code="));
        
        // Verify cache
        let code = location.split("code=").nth(1).unwrap();
        let identity = state.auth_code_cache.get(code).await;
        assert!(identity.is_some());
        assert_eq!(identity.unwrap().sub, "test-user");
    }

    #[tokio::test]
    async fn test_authorize_missing_header() {
        let mut rng = rand::thread_rng();
        let app_private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let app_private_key_pem = app_private_key.to_pkcs8_pem(Default::default()).unwrap().to_string();

        let settings = config::Settings {
            issuer: "http://localhost:8080".to_string(),
            grant_types_supported: vec![],
            port: 8080,
            upstream_oidc_url: "http://upstream-login".to_string(),
            upstream_jwks_url: "".to_string(),
            validate_upstream_token: true,
            private_key_path: "test/private_key.pem".to_string(),
            clients: vec![],
        };

        let state = Arc::new(AppState {
            settings,
            auth_code_cache: moka::future::Cache::builder().build(),
            jwks_cache: moka::future::Cache::builder().build(),
            key_state: key::KeyState::new(&app_private_key_pem),
        });

        let params = AuthorizeRequest {
            client_id: "client".to_string(),
            redirect_uri: "http://client/cb".to_string(),
            response_type: "code".to_string(),
            code_challenge: "challenge".to_string(),
        };

        let headers = HeaderMap::new(); // No Authorization header

        let response = authorize(State(state.clone()), Query(params), headers).await.into_response();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get("location").unwrap().to_str().unwrap(), "http://upstream-login");
    }
}