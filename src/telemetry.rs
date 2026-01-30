use opentelemetry::trace::TracerProvider;
use tracing_subscriber::{
    EnvFilter,
    fmt::format::FmtSpan,
    layer::{Layer, SubscriberExt},
    util::SubscriberInitExt,
};

use crate::config::{LoggingFormat, TelemetryConfig};

pub struct OtelGuard {
    tracer_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.tracer_provider.as_mut()
            && let Err(err) = provider.shutdown()
        {
            eprintln!("{err:?}");
        }
    }
}

fn resource(name: String) -> opentelemetry_sdk::Resource {
    opentelemetry_sdk::Resource::builder()
        .with_service_name(name.clone())
        .with_schema_url(
            [
                opentelemetry::KeyValue::new(
                    opentelemetry_semantic_conventions::attribute::SERVICE_VERSION,
                    env!("CARGO_PKG_VERSION"),
                ),
                opentelemetry::KeyValue::new(
                    opentelemetry_semantic_conventions::attribute::SERVICE_NAME,
                    name.clone(),
                ),
            ],
            opentelemetry_semantic_conventions::SCHEMA_URL,
        )
        .with_attributes(vec![opentelemetry::KeyValue::new("entity.name", name)])
        .build()
}

// Construct TracerProvider for OpenTelemetryLayer
fn init_tracer_provider(name: String) -> opentelemetry_sdk::trace::SdkTracerProvider {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .build()
        .unwrap();

    opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_sampler(opentelemetry_sdk::trace::Sampler::ParentBased(Box::new(
            opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(1.0),
        )))
        .with_id_generator(opentelemetry_sdk::trace::RandomIdGenerator::default())
        .with_resource(resource(name))
        .with_batch_exporter(exporter)
        .build()
}

// Initialize tracing-subscriber and return OtelGuard for opentelemetry-related termination processing
pub fn init(config: &TelemetryConfig) -> OtelGuard {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!(
            "{},axum={}",
            tracing::Level::from(config.level),
            tracing::Level::from(config.axum_level),
        ))
    });

    let fmt_layer = match config.format {
        LoggingFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .flatten_event(true)
            .with_span_events(FmtSpan::FULL)
            .with_target(true)
            .with_thread_ids(true)
            .with_line_number(true)
            .with_file(true)
            .boxed(),
        LoggingFormat::Pretty => tracing_subscriber::fmt::layer()
            .pretty()
            .with_span_events(FmtSpan::FULL)
            .with_target(true)
            .with_thread_ids(true)
            .with_line_number(true)
            .with_file(true)
            .boxed(),
    };

    let registry = tracing_subscriber::registry().with(filter).with(fmt_layer);

    if config.otlp_enabled {
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );

        let tracer_provider = init_tracer_provider(config.service_name.to_owned());
        let tracer = tracer_provider.tracer("tracing-otel-subscriber");

        registry
            .with(tracing_opentelemetry::OpenTelemetryLayer::new(tracer))
            .init();

        OtelGuard {
            tracer_provider: Some(tracer_provider),
        }
    } else {
        registry.init();
        OtelGuard {
            tracer_provider: None,
        }
    }
}
