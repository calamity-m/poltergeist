use crate::AppState;
use crate::jwks::Jwks;
use axum::http::{HeaderMap, StatusCode, header};
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Claims from the upstream IDP
#[derive(Debug, Deserialize, Serialize)]
pub struct UpstreamClaims {
    pub sub: String,
    pub email: String,
    pub exp: u64,
}

pub async fn get_upstream_identity(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<UpstreamClaims, (StatusCode, String)> {
    let upstream_token = match headers
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "))
    {
        Some(token) => token,
        None => {
            tracing::info!(audit = true, "No Authorization header found");
            return Err((
                StatusCode::UNAUTHORIZED,
                "Missing Authorization header".to_string(),
            ));
        }
    };

    if state.settings.validate_upstream_token {
        tracing::debug!("Validating upstream token against JWKS");
        decode_token_with_validation(state, upstream_token, &state.settings.upstream_jwks_url)
            .await
            .map_err(|e| {
                tracing::error!("Failed to validate upstream token: {}", e);
                (
                    StatusCode::UNAUTHORIZED,
                    "Invalid upstream token".to_string(),
                )
            })
    } else {
        tracing::debug!("Decoding upstream token without signature validation");
        decode_token_without_validation(upstream_token).map_err(|e| {
            tracing::error!("Failed to decode upstream token: {}", e);
            (
                StatusCode::BAD_REQUEST,
                "Invalid upstream token".to_string(),
            )
        })
    }
}

async fn decode_token_with_validation(
    state: &Arc<AppState>,
    token: &str,
    jwks_url: &str,
) -> Result<UpstreamClaims, anyhow::Error> {
    let header = decode_header(token)?;
    let kid = header.kid.ok_or_else(|| anyhow::anyhow!("Missing kid"))?;

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
    validation.validate_exp = false;
    let decoded = decode::<UpstreamClaims>(token, &decoding_key, &validation)?;

    Ok(decoded.claims)
}

fn decode_token_without_validation(token: &str) -> Result<UpstreamClaims, anyhow::Error> {
    let decoded = jsonwebtoken::dangerous::insecure_decode::<UpstreamClaims>(token)?;
    Ok(decoded.claims)
}
