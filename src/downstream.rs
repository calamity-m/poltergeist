use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{
    AppState, UserIdentity,
    config::{PrivateClient, PublicClient},
    upstream::UpstreamClaims,
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
}

pub async fn create_downstream_claims_for_public(
    state: &Arc<AppState>,
    client: &PublicClient,
    identity: UserIdentity,
) -> DownstreamClaims {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires_in = state.settings.token_expires_in;

    let aud = client.audience.clone();

    tracing::debug!("Issuing tokens with audience: {}", aud);

    let claims = DownstreamClaims {
        sub: identity.sub.clone(),
        aud: aud.to_string(),
        client_id: client.client_id.clone(),
        iss: state.settings.issuer.clone(),
        iat: now,
        exp: now + expires_in,
    };

    debug!("created claims - {:?}", claims);
    claims
}

pub async fn create_downstream_claims_for_private(
    state: &Arc<AppState>,
    client: &PrivateClient,
) -> DownstreamClaims {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires_in = state.settings.token_expires_in;

    let aud = client.audience.clone();

    tracing::debug!("Issuing M2M tokens with audience: {}", aud);

    let claims = DownstreamClaims {
        sub: client.client_id.clone(),
        aud,
        client_id: client.client_id.clone(),
        iss: state.settings.issuer.clone(),
        iat: now,
        exp: now + expires_in,
    };

    debug!("created claims - {:?}", claims);
    claims
}
