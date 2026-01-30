use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

mod config;

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    let settings = config::load_config();
    let shared_state = Arc::new(settings);

    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/", get(root))
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/jwks", get(jwks))
        .with_state(shared_state.clone());

    // run our app with hyper
    let addr = SocketAddr::from(([127, 0, 0, 1], shared_state.port));
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

async fn openid_configuration(
    State(settings): State<Arc<config::Settings>>,
) -> Json<OIDCConfig> {
    let config = OIDCConfig {
        issuer: settings.issuer.clone(),
        authorization_endpoint: format!("{}/authorize", settings.issuer),
        token_endpoint: format!("{}/token", settings.issuer),
        jwks_uri: format!("{}/jwks", settings.issuer),
        response_types_supported: vec!["code".to_string()],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["RS256".to_string()],
        grant_types_supported: settings.grant_types_supported.clone(),
    };
    Json(config)
}

#[derive(Deserialize)]
struct AuthorizeRequest {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    code_challenge: String,
    // we can ignore state and other params for now
}

async fn authorize(Query(params): Query<AuthorizeRequest>) -> impl IntoResponse {
    // TODO: Implement the authorize flow
    // 1. Check for Authorization header
    // 2. Decode upstream token
    // 3. Generate code and store in moka cache
    // 4. Redirect to redirect_uri
    (
        StatusCode::FOUND,
        [(
            "Location",
            format!("{}?code=some_code", params.redirect_uri),
        )],
    )
}

#[derive(Deserialize)]
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

async fn token(Json(_payload): Json<TokenRequest>) -> Json<TokenResponse> {
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

#[derive(Serialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Serialize)]
struct Jwk {
    kty: String,
    kid: String,
    n: String,
    e: String,
    alg: String,
    r#use: String,
}

async fn jwks() -> Json<Jwks> {
    // TODO: Return the JWKS JSON
    // This will expose the public key for verifying the tokens signed by this service
    let jwks = Jwks { keys: vec![] };
    Json(jwks)
}