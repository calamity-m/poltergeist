use std::{
    pin::Pin,
    task::{Context, Poll},
};

use axum::{extract::Request, http::HeaderMap, response::Response};
use opentelemetry::propagation::Extractor;
use tower::{Layer, Service};
use tracing::{Instrument, info, span, warn};
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub const REQUEST_ID_HEADER: &str = "x-request-id";

#[derive(Debug, Clone)]
pub struct TraceParentService<S> {
    inner: S,
}

impl<S> TraceParentService<S> {
    pub fn new(inner: S) -> Self {
        TraceParentService { inner }
    }
}

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

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for TraceParentService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    // Pin and box because instrumentation changes the future's type from S::Future
    // to Instrumented<S::Future>. Boxing erases the concrete type so we can
    // return Pin<Box<dyn Future<...>>> as required by our Service trait.
    // .instrument() attaches the span context to the future so all downstream
    // execution (route handlers, other middleware) happens within this span.
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

        let endpoint = req.uri().path().to_string();
        let http_method = req.method().to_string();

        let app_root = span!(
            tracing::Level::INFO,
            "request",
            endpoint = %endpoint,
            httpMethod = %http_method
        );

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

#[derive(Debug, Clone)]
pub struct TraceParentLayer {}

impl TraceParentLayer {
    pub fn new() -> Self {
        TraceParentLayer {}
    }
}

impl Default for TraceParentLayer {
    fn default() -> Self {
        TraceParentLayer::new()
    }
}

impl<S> Layer<S> for TraceParentLayer {
    type Service = TraceParentService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TraceParentService::new(inner)
    }
}
