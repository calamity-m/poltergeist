use axum::{
    Router,
    extract::State,
    response::Json,
    routing::{get, post},
};
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

mod authorize;
mod config;
mod token;

pub struct AppState {
    settings: config::Settings,
    auth_code_cache: Cache<String, UserIdentity>,
    jwks_cache: Cache<String, Jwks>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserIdentity {
    pub sub: String,
    pub email: String,
    pub groups: Vec<String>,
}

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    let settings = config::load_config();
    let auth_code_cache = Cache::builder()
        .time_to_live(Duration::from_secs(30))
        .build();
    let jwks_cache = Cache::builder()
        .time_to_live(Duration::from_secs(3600))
        .build();

    let shared_state = Arc::new(AppState {
        settings,
        auth_code_cache,
        jwks_cache,
    });

    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/", get(root))
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route("/authorize", get(authorize::authorize))
        .route("/token", post(token))
        .route("/jwks", get(jwks))
        .with_state(shared_state.clone());

    // run our app with hyper
    let addr = SocketAddr::from(([127, 0, 0, 1], shared_state.settings.port));
    tracing::debug!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// basic handler that responds with a static string
async fn root() -> &'static str {
    "Hello, World!"
}

#[derive(Serialize)]
struct OIDCConfig {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    grant_types_supported: Vec<String>,
}

async fn openid_configuration(State(state): State<Arc<AppState>>) -> Json<OIDCConfig> {
    let config = OIDCConfig {
        issuer: state.settings.issuer.clone(),
        authorization_endpoint: format!("{}/authorize", state.settings.issuer),
        token_endpoint: format!("{}/token", state.settings.issuer),
        jwks_uri: format!("{}/jwks", state.settings.issuer),
        response_types_supported: vec!["code".to_string()],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["RS256".to_string()],
        grant_types_supported: state.settings.grant_types_supported.clone(),
    };
    Json(config)
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    code_verifier: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    id_token: String,
    expires_in: u64,
}

async fn token(
    State(_state): State<Arc<AppState>>,
    Json(_payload): Json<TokenRequest>,
) -> Json<TokenResponse> {
    // TODO: Implement the token exchange flow
    // 1. Handle grant_type=authorization_code
    //    a. Retrieve code from moka cache
    //    b. Mint new ID and Access tokens
    //    c. Sign tokens with private key
    //    d. Return tokens
    // 2. Handle grant_type=client_credentials
    //    a. Validate client_id and client_secret
    //    b. Mint new Access token
    //    c. Sign token with private key
    //    d. Return token
    let token = TokenResponse {
        access_token: "some_access_token".to_string(),
        id_token: "some_id_token".to_string(),
        expires_in: 3600,
    };
    Json(token)
}

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

async fn jwks(State(_state): State<Arc<AppState>>) -> Json<Jwks> {
    // TODO: Return the JWKS JSON
    // This will expose the public key for verifying the tokens signed by this service
    let jwks = Jwks { keys: vec![] };
    Json(jwks)
}
