use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::SdkMeterProvider;

// For now, three buckets per decade (power of 10), grouping everything below 1 ms and above 5s
pub(crate) const TIMING_HISTOGRAM_BUCKET_BOUNDARIES: &[f64] = &[
    0.0, 1e-3, 2e-3, 5e-3, 1e-2, 2e-2, 5e-2, 1e-1, 2e-1, 5e-1, 1.0, 2.0, 5.0,
];

fn build_otlp_exporter() -> Option<opentelemetry_otlp::MetricExporter> {
    let otlp_url = match std::env::var("OTEL_METRICS_EXPORT_DESTINATION") {
        Ok(otlp_url) => otlp_url,
        Err(std::env::VarError::NotPresent) => return None,
        Err(_) => {
            tracing::error!("Malformed url for metrics export");
            return None;
        }
    };

    match opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_endpoint(otlp_url)
        .build()
    {
        Ok(exporter) => Some(exporter),
        Err(e) => {
            tracing::error!("Could not start metrics exporter: {}", e);
            None
        }
    }
}

pub fn telemetry_init() {
    let builder = SdkMeterProvider::builder();
    let builder = if let Some(exporter) = build_otlp_exporter() {
        builder.with_periodic_exporter(exporter)
    } else {
        builder.with_periodic_exporter(opentelemetry_stdout::MetricExporter::default())
    };
    opentelemetry::global::set_meter_provider(builder.build());
}
