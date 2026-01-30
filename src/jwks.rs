use crate::AppState;
use axum::extract::State;
use axum::response::Json;
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

pub async fn jwks(State(state): State<Arc<AppState>>) -> Json<Jwks> {
    Json(state.key_state.jwks_json.clone())
}
