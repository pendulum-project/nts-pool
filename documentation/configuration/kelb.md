# KELB Configuration

## Environment variables

- `OTEL_METRICS_EXPORT_DESTINATION`: Http endpoint to which the otlp metrics should be delivered. No value sends metrics to stdout instead.
- `OTEL_METRICS_EXPORT_INTERVAL`: Interval in milliseconds of how often to send metrics. Default value is 60000 (60 seconds).
