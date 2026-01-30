//! Logic for the `/jwks` endpoint.
//!
//! Serves the JSON Web Key Set (JWKS) containing the public key(s) used
//! to verify tokens signed by this OIDC provider.

use crate::AppState;
use axum::{
    extract::State,
    http::header,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A JSON Web Key Set.
#[derive(Clone, Serialize, Deserialize)]
pub struct Jwks {
    /// List of keys.
    pub keys: Vec<Jwk>,
}

/// A JSON Web Key.
#[derive(Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (e.g., "RSA").
    pub kty: String,
    /// Key ID.
    pub kid: String,
    /// Modulus (Base64URL encoded).
    pub n: String,
    /// Exponent (Base64URL encoded).
    pub e: String,
    /// Algorithm (e.g., "RS256").
    pub alg: String,
    /// Key use (e.g., "sig").
    pub r#use: String,
}

/// Handler for the `/jwks` endpoint.
///
/// Returns the pre-computed JWKS JSON string.
pub async fn jwks(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // We already have the JSON string pre-computed, so we return it directly
    // to avoid double-serialization overhead.
    (
        [(header::CONTENT_TYPE, "application/json")],
        state.key_state.jwks_json.clone(),
    )
}