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

mod authorize;
mod config;
mod jwks;
mod jwt;
mod key;
mod middleware;
mod telemetry;
mod token;
mod userinfo;

/// Global application state shared across handlers.
pub struct AppState {
    /// Application configuration loaded from `config.yaml`.
    settings: config::Settings,
    /// Cache for upstream JWKS to avoid frequent network requests during token validation.
    jwks_cache: Cache<String, jwks::Jwks>,
    /// Cache for authorization codes to support confidential clients.
    auth_code_cache: Cache<String, jwt::upstream::AuthorizationCodeContext>,
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

    let app = create_app(shared_state.clone());

    // run our app with hyper
    let addr = SocketAddr::from(([0, 0, 0, 0], shared_state.settings.port));
    tracing::info!("Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn create_app(state: Arc<AppState>) -> Router {
    Router::new()
        // `GET /` goes to `root`
        .route("/", get(root))
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route(
            &state.settings.authorize_path,
            get(authorize::authorize_get).post(authorize::authorize_post),
        )
        .route(&state.settings.token_path, post(token::token))
        .route(&state.settings.userinfo_path, get(userinfo::userinfo))
        .route(&state.settings.jwks_path, get(jwks::jwks))
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
        .layer(middleware::AuditLayer)
        .layer(middleware::TraceParentLayer)
        .with_state(state)
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
    userinfo_endpoint: String,
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
        authorization_endpoint: format!("{}{}", state.settings.issuer, state.settings.authorize_path),
        token_endpoint: format!("{}{}", state.settings.issuer, state.settings.token_path),
        userinfo_endpoint: format!("{}{}", state.settings.issuer, state.settings.userinfo_path),
        jwks_uri: format!("{}{}", state.settings.issuer, state.settings.jwks_path),
        response_types_supported: vec!["code".to_string()],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["RS256".to_string()],
        grant_types_supported: state.settings.grant_types_supported.clone(),
    };
    Json(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_configurable_endpoints() {
        let private_key_pem = std::fs::read_to_string("test/private_key.pem").unwrap();
        let key_state = key::KeyState::new(&private_key_pem);

        let settings = config::Settings {
            authorize_path: "/custom-authorize".to_string(),
            token_path: "/custom-token".to_string(),
            ..config::Settings::default()
        };

        let state = Arc::new(AppState {
            settings,
            jwks_cache: Cache::builder().build(),
            auth_code_cache: Cache::builder().build(),
            key_state,
        });

        let app = create_app(state);

        // Test custom authorize endpoint
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/custom-authorize?client_id=test&response_type=code&redirect_uri=http://cb")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        
        // Should not be 404 (likely 302 redirect to upstream or 400 if validation fails, 
        // but since we don't have upstream header, it will likely be 302 to upstream or 400 invalid client)
        assert_ne!(response.status(), StatusCode::NOT_FOUND);

        // Test that default endpoint is NOT found
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/authorize")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        
        // Test custom token endpoint
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/custom-token")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"grant_type":"client_credentials","client_id":"foo","client_secret":"bar"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_ne!(response.status(), StatusCode::NOT_FOUND);
    }
}