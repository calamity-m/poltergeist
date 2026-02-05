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
    routing::{get, post},
};
use moka::future::Cache;
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
mod well_known;

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
        std::fs::read_to_string(&settings.signing_key_path).expect("Failed to read private key");
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
    let mut oidc_router = Router::new()
        .route(
            &state.settings.well_known_path,
            get(well_known::openid_configuration),
        );

    for secondary in &state.settings.secondary_well_known {
        let secondary_clone = secondary.clone();
        oidc_router = oidc_router.route(
            &secondary.path,
            get(move |state: State<Arc<AppState>>| {
                well_known::secondary_openid_configuration(state, secondary_clone)
            }),
        );
    }

    oidc_router = oidc_router
        .route(
            &state.settings.authorize_path,
            get(authorize::authorize_get).post(authorize::authorize_post),
        )
        .route(&state.settings.token_path, post(token::token))
        .route(&state.settings.jwks_path, get(jwks::jwks))
        .route(&state.settings.userinfo_path, get(userinfo::userinfo));

    Router::new()
        .route("/", get(root))
        .nest(&state.settings.context_path, oidc_router)
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
            context_path: "/oidc".to_string(),
            authorize_path: "/custom-authorize".to_string(),
            token_path: "/custom-token".to_string(),
            jwks_path: "/custom-jwks".to_string(),
            userinfo_path: "/custom-userinfo".to_string(),
            well_known_path: "/custom-discovery".to_string(),
            secondary_well_known: vec![config::SecondaryWellKnownConfiguration {
                path: "/secondary-discovery".to_string(),
                authorization_host: "http://auth-ext".to_string(),
                token_host: "http://token-ext".to_string(),
                jwks_host: "http://jwks-ext".to_string(),
                userinfo_host: "http://userinfo-ext".to_string(),
            }],
            ..config::Settings::default()
        };

        let state = Arc::new(AppState {
            settings,
            jwks_cache: Cache::builder().build(),
            auth_code_cache: Cache::builder().build(),
            key_state,
        });

        let app = create_app(state);

        // ... (previous tests)

        // Test custom well-known endpoint
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/oidc/custom-discovery")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Test secondary well-known endpoint
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/oidc/secondary-discovery")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 2048).await.unwrap();
        let config: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(config["authorization_endpoint"], "http://auth-ext/oidc/custom-authorize");
        assert_eq!(config["token_endpoint"], "http://token-ext/oidc/custom-token");
    }
}