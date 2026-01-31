//! cryptographic key management.
//!
//! Handles loading the private signing key and generating the corresponding
//! public key JWKS (JSON Web Key Set).

use crate::jwks::{Jwk, Jwks};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{DecodingKey, EncodingKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};

/// Holds the application's cryptographic keys.
#[derive(Clone)]
pub struct KeyState {
    /// The private key used for signing JWTs.
    pub encoding_key: EncodingKey,
    /// The public key used for validating JWTs signed by us.
    pub decoding_key: DecodingKey,
    /// The pre-computed JWKS JSON string.
    /// Served directly by the `/jwks` endpoint.
    pub jwks_json: String,
}

impl KeyState {
    /// Loads the private key from a PEM string and prepares the key state.
    ///
    /// # Arguments
    /// * `private_key_pem` - The RSA private key in PKCS#8 PEM format.
    ///
    /// # Panics
    /// Panics if the key cannot be parsed.
    #[tracing::instrument(skip(private_key_pem))]
    pub fn new(private_key_pem: &str) -> Self {
        // 1. Load Private Key for Signing (jsonwebtoken)
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .expect("Failed to parse private key PEM");

        // 2. Load Private Key again using RSA crate to derive Public Key components
        // (jsonwebtoken doesn't expose the raw 'n' and 'e' easily)
        let private_key_obj = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
            .expect("Failed to load private key for inspection");
        let public_key_obj = private_key_obj.to_public_key();

        // 3. Generate JWKS JSON once at startup
        let jwks_json = generate_jwks_json(&public_key_obj, "poltergeist");

        // 4. Create DecodingKey from public key components for internal validation
        let n_str = URL_SAFE_NO_PAD.encode(public_key_obj.n().to_bytes_be());
        let e_str = URL_SAFE_NO_PAD.encode(public_key_obj.e().to_bytes_be());
        let decoding_key = DecodingKey::from_rsa_components(&n_str, &e_str)
            .expect("Failed to create decoding key");

        Self {
            encoding_key,
            decoding_key,
            jwks_json,
        }
    }
}

/// Generates the JWKS JSON string from an RSA public key.
#[tracing::instrument(skip(public_key))]
fn generate_jwks_json(public_key: &RsaPublicKey, kid: &str) -> String {
    // 3. Extract components for OIDC JWKS (Base64URL encoded)
    let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

    // 4. Construct the JSON Web Key Set
    let jwks = Jwks {
        keys: vec![Jwk {
            kty: "RSA".to_string(),
            r#use: "sig".to_string(),
            kid: kid.to_string(),
            alg: "RS256".to_string(),
            n,
            e,
        }],
    };
    serde_json::to_string(&jwks).unwrap()
}