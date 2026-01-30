use serde::{Deserialize, Serialize};

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
