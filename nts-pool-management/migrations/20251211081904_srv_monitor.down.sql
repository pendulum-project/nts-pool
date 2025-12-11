-- Removing values from enums is a bit of a problem. This gives several challenges:
--  - Old monitor records for SRV pool, these we just delete.
--  - Values cannot be deleted from an enum type. We can work around this by
--    recreating the type and altering any columns that use it.
--  - Unfortunately, columns that are used in views cannot have their types changed.
--    We work around this by removing the view before the alter operation and recreating
--    it afterwards.
DELETE FROM monitor_samples WHERE protocol != 'ipv4' AND protocol != 'ipv6';
CREATE TYPE ip_protocol_new AS ENUM ('ipv4', 'ipv6');
DROP VIEW time_source_scores;
ALTER TABLE monitor_samples 
  ALTER COLUMN protocol TYPE ip_protocol_new
    USING (protocol::text::ip_protocol_new);
DROP TYPE ip_protocol;
ALTER TYPE ip_protocol_new RENAME TO ip_protocol;
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
