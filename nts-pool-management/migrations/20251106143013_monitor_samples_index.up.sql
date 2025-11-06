-- Add up migration script here
CREATE INDEX monitor_sample_fetching ON monitor_samples (time_source_id, received_at);
