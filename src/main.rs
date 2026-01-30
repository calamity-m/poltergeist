//! Poltergeist: A "Performative" OIDC Shim.
//!
//! This application serves as a lightweight OIDC provider that bridges authentication
//! from an upstream source (e.g., an Ingress controller).
//!
//! It implements standard OIDC endpoints (`/authorize`, `/token`, `/jwks`, `/.well-known/openid-configuration`)
//! and uses in-memory caching for state management.

use axum::{
    Router,
    extract::State,
    response::Json,
    routing::{get, post},
};
use moka::future::Cache;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::trace::{DefaultOnFailure, DefaultOnRequest, DefaultOnResponse};
use tracing::Level;

mod audit;
mod authorize;
mod config;
mod downstream;
mod jwks;
mod key;
mod middleware;
mod telemetry;
mod token;
mod upstream;

/// Global application state shared across handlers.
pub struct AppState {
    /// Application configuration loaded from `config.yaml`.
    settings: config::Settings,
    /// Cache for upstream JWKS to avoid frequent network requests during token validation.
    jwks_cache: Cache<String, jwks::Jwks>,
    /// Cache for authorization codes to support confidential clients.
    auth_code_cache: Cache<String, upstream::UpstreamClaims>,
    /// State managing the application's signing keys and pre-computed JWKS.
    key_state: key::KeyState,
}

#[tokio::main]
async fn main() {
    let settings = config::load_config();
    let _otel_guard = telemetry::init(&settings.telemetry);

    tracing::info!("Starting Poltergeist OIDC Shim...");
    tracing::info!("Configuration loaded successfully. Port: {}", settings.port);

    // Initialize caches with appropriate TTLs
    let jwks_cache = Cache::builder()
        .time_to_live(Duration::from_secs(3600))
        .build();

    let auth_code_cache = Cache::builder()
        .time_to_live(Duration::from_secs(60))
        .build();

    let private_key_pem =
        std::fs::read_to_string(&settings.private_key_path).expect("Failed to read private key");
    let key_state = key::KeyState::new(&private_key_pem);
    tracing::info!("Cryptographic keys initialized.");

    let shared_state = Arc::new(AppState {
        settings,
        jwks_cache,
        auth_code_cache,
        key_state,
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
        .route("/token", post(token::token))
        .route("/jwks", get(jwks::jwks))
        .layer(
            tower_http::trace::TraceLayer::new_for_http()
                .on_failure(DefaultOnFailure::new().level(Level::ERROR))
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(
                    DefaultOnResponse::new()
                        .include_headers(true)
                        .level(Level::INFO),
                ),
        )
        .layer(middleware::TraceParentLayer::default())
        .with_state(shared_state.clone());

    // run our app with hyper
    let addr = SocketAddr::from(([127, 0, 0, 1], shared_state.settings.port));
    tracing::info!("Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// Basic health check endpoint.
#[tracing::instrument]
async fn root() -> &'static str {
    "Hello, World!"
}

/// Structure representing the OIDC Discovery document.
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

/// Handler for the OIDC Discovery endpoint (`/.well-known/openid-configuration`).
/// Returns the configuration metadata for this OIDC provider.
#[tracing::instrument(skip(state))]
async fn openid_configuration(State(state): State<Arc<AppState>>) -> Json<OIDCConfig> {
    tracing::debug!("Serving OIDC discovery configuration");
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
