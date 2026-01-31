//! Custom Axum/Tower middlewares for Poltergeist.
//!
//! This module provides:
//! - `TraceParentLayer`: Propagation of OpenTelemetry trace contexts from incoming headers.
//! - `AuditLayer`: Structured logging for authentication events and request auditing.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{extract::Request, http::HeaderMap, response::Response};
use opentelemetry::propagation::Extractor;
use tower::{Layer, Service};
use tracing::{Instrument, info, span, warn};
use tracing_opentelemetry::OpenTelemetrySpanExt;

// --- TraceParent Middleware ---

pub struct HeaderExtractor<'a> {
    headers: &'a HeaderMap,
}

impl<'a> Extractor for HeaderExtractor<'a> {
    fn get(&self, key: &str) -> Option<&str> {
        self.headers
            .get(key)
            .and_then(|header| header.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.headers.keys().map(|h| h.as_str()).collect()
    }
}

#[derive(Debug, Clone)]
pub struct TraceParentService<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for TraceParentService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let parent_context = opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.extract(&HeaderExtractor {
                headers: req.headers(),
            })
        });

        let app_root = span!(tracing::Level::INFO, "request");

        if let Err(err) = app_root.set_parent(parent_context) {
            warn!(
                error = debug(err),
                "unable to set otel parent, span will be new instead"
            );
        } else {
            info!(
                traceparent = ?req.headers().get("traceparent"),
                "trace parent set"
            )
        }

        Box::pin(self.inner.call(req).instrument(app_root))
    }
}

/// A layer that extracts the `traceparent` header and sets it as the parent of the current tracing span.
///
/// This ensures that Poltergeist's logs and spans are correctly linked to the upstream
/// request (e.g., from an Ingress or another microservice).
#[derive(Debug, Clone, Default)]
pub struct TraceParentLayer;

impl<S> Layer<S> for TraceParentLayer {
    type Service = TraceParentService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TraceParentService { inner }
    }
}

// --- Audit Middleware ---

#[derive(Debug, Clone)]
pub struct AuditService<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for AuditService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let endpoint = req.uri().path().to_string();
        let method = req.method().to_string();
        let host = req
            .headers()
            .get("x-forwarded-host")
            .and_then(|h| h.to_str().ok())
            .or_else(|| req.headers().get("host").and_then(|h| h.to_str().ok()))
            .unwrap_or("")
            .to_string();

        let fut = self.inner.call(req);
        Box::pin(async move {
            let response = fut.await;

            if let Ok(ref res) = response {
                tracing::info!(
                    audit = true,
                    auditType = "authentication",
                    endpoint = %endpoint,
                    host = %host,
                    httpMethod = %method,
                    status = %res.status().as_u16(),
                    "request to {} finished",
                    endpoint
                );
            }

            response
        })
    }
}

/// A layer that logs structured audit events for every request.
///
/// Logs include information about the endpoint, host, HTTP method, and status code,
/// specifically tagged with `audit = true` for easy filtering in log aggregation tools.
#[derive(Debug, Clone, Default)]
pub struct AuditLayer;

impl<S> Layer<S> for AuditLayer {
    type Service = AuditService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuditService { inner }
    }
}
