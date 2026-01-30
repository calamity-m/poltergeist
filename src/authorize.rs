use crate::{AppState, Jwks, UserIdentity};
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
};
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct AuthorizeRequest {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    code_challenge: String,
    // we can ignore state and other params for now
}

#[derive(Debug, Deserialize)]
struct UpstreamClaims {
    sub: String,
    email: String,
    groups: Vec<String>,
}

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

    let user_identity = if state.settings.validate_upstream_token {
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

    let auth_code = generate_random_code();
    state
        .auth_code_cache
        .insert(auth_code.clone(), user_identity)
        .await;

    let redirect_url = format!("{}?code={}", params.redirect_uri, auth_code);
    Redirect::to(&redirect_url).into_response()
}

fn generate_random_code() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect()
}

async fn decode_token_with_validation(
    state: &Arc<AppState>,
    token: &str,
    jwks_url: &str,
) -> Result<UserIdentity, anyhow::Error> {
    let header = decode_header(token)?;
    let kid = header.kid.ok_or_else(|| anyhow::anyhow!("Missing kid"))?;

    let jwks = state
        .jwks_cache
        .try_get_with(jwks_url.to_string(), async {
            let jwks: Jwks = reqwest::get(jwks_url).await?.json().await?;
            Ok::<_, anyhow::Error>(jwks)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch or cache JWKS: {}", e))?;

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
    })
}

fn decode_token_without_validation(token: &str) -> Result<UserIdentity, anyhow::Error> {
    let decoded = jsonwebtoken::dangerous::insecure_decode::<UpstreamClaims>(token)?;
    Ok(UserIdentity {
        sub: decoded.claims.sub,
        email: decoded.claims.email,
        groups: decoded.claims.groups,
    })
}
