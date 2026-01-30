use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::EncodingKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::json;

use crate::AppState;
use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: String,
    pub n: String,
    pub e: String,
    pub alg: String,
    pub r#use: String,
}

pub async fn jwks(State(state): State<Arc<AppState>>) -> Json<String> {
    panic!("todo");
}

#[derive(Clone)]
pub struct KeyState {
    pub encoding_key: EncodingKey, // For jsonwebtoken signing
    pub jwks_json: String,         // Pre-computed JWKS response
}

impl KeyState {
    pub fn new(private_key_pem: &str) -> Self {
        // 1. Load Private Key for Signing (jsonwebtoken)
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .expect("Failed to parse private key PEM");

        // 2. Load Private Key again using RSA crate to derive Public Key components
        let private_key_obj = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
            .expect("Failed to load private key for inspection");
        let public_key_obj = private_key_obj.to_public_key();

        // 3. Generate JWKS JSON once at startup
        let jwks_json = generate_jwks_json(&public_key_obj, "poltergeist");

        Self {
            encoding_key,
            jwks_json,
        }
    }
}

fn generate_jwks_json(public_key: &RsaPublicKey, kid: &str) -> String {
    // 3. Extract components for OIDC JWKS (Base64URL encoded)
    let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

    // 4. Construct the JSON Web Key Set
    json!({
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": kid,
                "alg": "RS256",
                "n": n,
                "e": e
            }
        ]
    })
    .to_string()
}
