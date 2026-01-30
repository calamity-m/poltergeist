//! Logic for the `/token` endpoint.
//!
//! Handles the exchange of authorization codes (or client credentials) for access and ID tokens.

use crate::AppState;
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Parameters for the token exchange request.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct TokenRequest {
    /// The grant type (e.g., "authorization_code" or "client_credentials").
    grant_type: String,
    /// The authorization code received from the `/authorize` endpoint.
    code: Option<String>,
    /// PKCE code verifier (currently ignored but part of the spec).
    code_verifier: Option<String>,
    /// Client identifier.
    client_id: Option<String>,
    /// Client secret (for client_credentials flow).
    client_secret: Option<String>,
}

/// The response containing the issued tokens.
#[derive(Serialize)]
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
/// **TODO:** Implement the full token exchange logic.
/// Currently returns a placeholder stub response.
///
/// Expected flow:
/// 1.  Validate the `grant_type`.
/// 2.  If `authorization_code`:
///     *   Retrieve the user identity associated with the `code` from the cache.
///     *   Mint new ID and Access tokens signed with the application's private key.
/// 3.  If `client_credentials`:
///     *   Validate `client_id` and `client_secret`.
///     *   Mint a new Access token for the service account.
pub async fn token(
    State(_state): State<Arc<AppState>>,
    Json(_payload): Json<TokenRequest>,
) -> Json<TokenResponse> {
    // TODO: Implement the token exchange flow
    let token = TokenResponse {
        access_token: "some_access_token".to_string(),
        id_token: "some_id_token".to_string(),
        expires_in: 3600,
    };
    Json(token)
}