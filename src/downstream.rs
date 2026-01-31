use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::debug;

use crate::{
    AppState,
    config::PrivateClient,
};

/// JWT claims for the tokens issued by Poltergeist,
/// which will be sent downstream
#[derive(Debug, Serialize, Deserialize)]
pub struct DownstreamClaims {
    /// Subject identifier - copied from the upstream token for public clients,
    /// or forced to be the client_id
    pub sub: String,
    /// Audience.
    pub aud: String,
    /// Client ID
    pub client_id: String,
    /// Issuer.
    pub iss: String,
    /// Expiration time (UNIX timestamp).
    pub exp: u64,
    /// Issued at (UNIX timestamp).
    pub iat: u64,
    /// Nonce (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Everything else lands here
    #[serde(flatten)]
    pub other: HashMap<String, Value>,
}

pub fn create_downstream_claims(
    issuer: String,
    token_expires_in: u64,
    client_id: String,
    audience: String,
    subject: String,
    nonce: Option<String>,
    other: HashMap<String, Value>,
) -> DownstreamClaims {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let claims = DownstreamClaims {
        sub: subject,
        aud: audience,
        client_id,
        iss: issuer,
        iat: now,
        exp: now + token_expires_in,
        nonce,
        other,
    };

    debug!("created claims - {:?}", claims);
    claims
}

pub async fn create_downstream_claims_for_private(
    state: &Arc<AppState>,
    client: &PrivateClient,
) -> DownstreamClaims {
    create_downstream_claims(
        state.settings.issuer.clone(),
        state.settings.token_expires_in,
        client.client_id.clone(),
        client.audience.clone(),
        client.client_id.clone(),
        None,
        HashMap::new(),
    )
}
