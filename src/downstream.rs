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

/// Generic builder for creating downstream tokens.
///
/// This function constructs the standard JWT claims, sets the expiration and issued-at times,
/// and ensures that any additional claims provided in the `other` map do not conflict
/// with the standard OIDC fields (sub, aud, iss, etc.).
///
/// Used by both authorization code flow (where `other` comes from upstream user identity)
/// and client credentials flow (via `create_downstream_claims_for_private`).
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

    // Sanitize the 'other' map to ensure it doesn't contain keys
    // that conflict with our explicitly defined claims.
    let mut other = other;
    other.remove("sub");
    other.remove("aud");
    other.remove("client_id");
    other.remove("iss");
    other.remove("exp");
    other.remove("iat");
    other.remove("nonce");

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

/// Specialized builder for Machine-to-Machine (M2M) tokens.
///
/// This is a convenience wrapper around `create_downstream_claims` for the
/// Client Credentials grant.
///
/// Key differences:
/// *   **Subject (`sub`):** Forced to be the `client_id` (since there is no human user).
/// *   **Nonce:** Always `None` (not used in M2M).
/// *   **Other Claims:** Always empty (no upstream identity to merge).
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_claims_precedence() {
        let mut other = HashMap::new();
        // Attempt to override 'sub' in the flattened map
        other.insert("sub".to_string(), json!("malicious-override"));
        other.insert("custom-claim".to_string(), json!("custom-value"));

        let claims = create_downstream_claims(
            "real-issuer".to_string(),
            1000,
            "real-client".to_string(),
            "real-audience".to_string(),
            "real-subject".to_string(),
            None,
            other,
        );

        // Serialize to JSON
        let serialized = serde_json::to_value(&claims).unwrap();
        
        // In serde_json, if we have duplicate keys during serialization from flatten, 
        // the behavior can be tricky. But usually, the struct fields are serialized first.
        // Let's see what actually happens.
        
        assert_eq!(serialized["sub"], json!("real-subject"));
        assert_eq!(serialized["custom-claim"], json!("custom-value"));

        // Deserialize back to DownstreamClaims
        // When deserializing, serde(flatten) with a map will put ALL unknown fields into the map.
        // Known fields (sub, aud, etc.) will be populated into their respective struct fields.
        let deserialized: DownstreamClaims = serde_json::from_value(serialized).unwrap();
        
        assert_eq!(deserialized.sub, "real-subject");
        assert_eq!(deserialized.other.get("custom-claim").unwrap(), &json!("custom-value"));
        // The 'sub' should NOT be in the other map after round-trip if it was a known field,
        // UNLESS it was duplicated in the JSON.
        assert!(!deserialized.other.contains_key("sub"));
    }
}
