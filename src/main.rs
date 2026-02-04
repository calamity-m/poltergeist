//! Poltergeist: A "Performative" OIDC Shim.
//!
//! This application serves as a lightweight OIDC provider that bridges authentication
//! from an upstream source (e.g., an Ingress controller).
//!
//! It implements standard OIDC endpoints (`/authorize`, `/token`, `/jwks`, `/.well-known/openid-configuration`)
//! and uses in-memory caching for state management.

use axum::{
    Router,
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
    let mut router = Router::new()
        // `GET /` goes to `root`
        .route("/", get(root));

    for path in &state.settings.well_known_paths {
        router = router.route(path, get(well_known::openid_configuration));
    }

    router = router.route(
        &state.settings.authorize_path,
        get(authorize::authorize_get).post(authorize::authorize_post),
    );

    for path in &state.settings.token_paths {
        router = router.route(path, post(token::token));
    }

    for path in &state.settings.jwks_paths {
        router = router.route(path, get(jwks::jwks));
    }

    for path in &state.settings.userinfo_paths {
        router = router.route(path, get(userinfo::userinfo));
    }

    router
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
            authorize_path: "/custom-authorize".to_string(),
            token_paths: vec!["/custom-token".to_string(), "/another-token".to_string()],
            jwks_paths: vec!["/custom-jwks".to_string(), "/hidden-jwks".to_string()],
            userinfo_paths: vec!["/custom-userinfo".to_string(), "/hidden-userinfo".to_string()],
            well_known_paths: vec!["/custom-discovery".to_string(), "/another-discovery".to_string()],
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

        // Test another custom token endpoint
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/another-token")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"grant_type":"client_credentials","client_id":"foo","client_secret":"bar"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_ne!(response.status(), StatusCode::NOT_FOUND);

        // Test custom well-known endpoint
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/custom-discovery")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Test another custom well-known endpoint
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/another-discovery")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Test custom JWKS endpoint
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/custom-jwks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Test another custom JWKS endpoint
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/hidden-jwks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Test custom UserInfo endpoint
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/custom-userinfo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Not found because we don't provide a token, but it should be 401/400 not 404
        assert_ne!(response.status(), StatusCode::NOT_FOUND);

        // Test another custom UserInfo endpoint
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/hidden-userinfo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_ne!(response.status(), StatusCode::NOT_FOUND);

        // Test that default well-known endpoint is NOT found
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}