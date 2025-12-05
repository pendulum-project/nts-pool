-- Add up migration script here
CREATE INDEX monitor_sample_score_idx ON monitor_samples (time_source_id, monitor_id, protocol, received_at DESC);

CREATE VIEW time_source_scores AS WITH latest_per_monitor AS (
	SELECT DISTINCT ON (time_source_id, monitor_id, protocol) *
	FROM monitor_samples
	ORDER BY time_source_id, monitor_id, protocol, received_at DESC
),
best_per_source AS (
    SELECT DISTINCT ON (time_source_id, protocol) *
    FROM latest_per_monitor
    ORDER BY time_source_id, protocol, score DESC
)
SELECT ts.*, COALESCE(v4.score, 0) AS "ipv4_score", COALESCE(v6.score, 0) AS "ipv6_score"
FROM time_sources AS ts
LEFT JOIN best_per_source AS v4 ON v4.time_source_id = ts.id AND v4.protocol = 'ipv4'
LEFT JOIN best_per_source AS v6 ON v6.time_source_id = ts.id AND v6.protocol = 'ipv6';
