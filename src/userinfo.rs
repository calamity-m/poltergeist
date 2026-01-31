//! Logic for the `/userinfo` endpoint.
//!
//! Validates the access token (issued by Poltergeist) and returns the claims.

use crate::{AppState, downstream::DownstreamClaims};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::Json,
};
use jsonwebtoken::{Algorithm, Validation, decode};
use std::sync::Arc;

/// Handler for the `/userinfo` endpoint.
#[tracing::instrument(skip(state, headers))]
pub async fn userinfo(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<DownstreamClaims>, (StatusCode, String)> {
    // 1. Extract the token from Authorization header
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header".to_string()))?
        .to_str()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid Authorization header".to_string()))?;

    if !auth_header.starts_with("Bearer ") {
        return Err((StatusCode::BAD_REQUEST, "Invalid auth scheme".to_string()));
    }

    let token = &auth_header["Bearer ".len()..];

    // 2. Validate the token using our own public key
    // We configured validation to expect RS256.
    // We should also validate audience and issuer if possible, but for now we rely on signature.
    // NOTE: validation.validate_exp is true by default.
    let mut validation = Validation::new(Algorithm::RS256);
    // We set the required audience to nothing for now, or we could check against specific clients.
    // Since we don't know which client is calling, validation of audience is tricky without more context
    // or simply disabling it if we trust the signature (since we signed it).
    // For strictness, we might want to check if the audience matches *any* known client, but 
    // simply validating the signature and expiration is usually sufficient for UserInfo 
    // as long as the token was issued by us.
    validation.validate_aud = false; 

    let token_data = decode::<DownstreamClaims>(
        token,
        &state.key_state.decoding_key,
        &validation,
    ).map_err(|e| {
        tracing::warn!("Failed to validate token at userinfo: {}", e);
        (StatusCode::UNAUTHORIZED, "Invalid token".to_string())
    })?;

    tracing::info!("Served userinfo for subject: {}", token_data.claims.sub);

    Ok(Json(token_data.claims))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::config::Settings;
    use crate::key::KeyState;
    use moka::future::Cache;
    use jsonwebtoken::{Header, encode};

    #[tokio::test]
    async fn test_userinfo_success() {
        let private_key_pem = std::fs::read_to_string("test/private_key.pem").unwrap();
        let key_state = KeyState::new(&private_key_pem);

        let settings = Settings {
            issuer: "http://localhost:8080".to_string(),
            grant_types_supported: vec![],
            port: 8080,
            upstream_oidc_url: "http://upstream".to_string(),
            upstream_jwks_url: "http://upstream/jwks".to_string(),
            validate_upstream_token: false,
            private_key_path: "test/private_key.pem".to_string(),
            token_expires_in: 3600,
            private_clients: vec![],
            public_clients: vec![],
            telemetry: Default::default(),
        };

        let state = Arc::new(AppState {
            settings,
            jwks_cache: Cache::builder().build(),
            auth_code_cache: Cache::builder().build(),
            key_state: key_state.clone(),
        });

        // Mint a valid token
        let claims = crate::downstream::create_downstream_claims(
            "http://localhost:8080".to_string(),
            3600,
            "client-id".to_string(),
            "aud".to_string(),
            "user-123".to_string(),
            None,
            HashMap::new(),
        );

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("poltergeist".to_string());

        let token = encode(
            &header,
            &claims,
            &key_state.encoding_key,
        ).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", token).parse().unwrap(),
        );

        let result = userinfo(State(state), headers).await;
        assert!(result.is_ok());
        let claims = result.unwrap().0;
        assert_eq!(claims.sub, "user-123");
    }

    #[tokio::test]
    async fn test_userinfo_invalid_token() {
        let private_key_pem = std::fs::read_to_string("test/private_key.pem").unwrap();
        let key_state = KeyState::new(&private_key_pem);
        let settings = Settings {
            issuer: "http://localhost:8080".to_string(),
            grant_types_supported: vec![],
            port: 8080,
            upstream_oidc_url: "http://upstream".to_string(),
            upstream_jwks_url: "http://upstream/jwks".to_string(),
            validate_upstream_token: false,
            private_key_path: "test/private_key.pem".to_string(),
            token_expires_in: 3600,
            private_clients: vec![],
            public_clients: vec![],
            telemetry: Default::default(),
        };

        let state = Arc::new(AppState {
            settings,
            jwks_cache: Cache::builder().build(),
            auth_code_cache: Cache::builder().build(),
            key_state,
        });

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer invalid-token".parse().unwrap(),
        );

        let result = userinfo(State(state), headers).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, StatusCode::UNAUTHORIZED);
    }
}
