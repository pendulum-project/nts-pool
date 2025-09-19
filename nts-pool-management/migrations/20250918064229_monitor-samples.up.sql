-- Add up migration script here
CREATE TYPE ip_protocol AS ENUM ('ipv4', 'ipv6');

CREATE TABLE monitor_samples (
    time_source_id UUID REFERENCES time_sources(id) ON DELETE CASCADE,
    protocol ip_protocol,
    monitor_id UUID REFERENCES monitors(id) ON DELETE RESTRICT,
    received_at TIMESTAMPTZ DEFAULT NOW(),
    score FLOAT NOT NULL,
    raw_sample JSONB NOT NULL,
    PRIMARY KEY (time_source_id, protocol, monitor_id, received_at)
);
