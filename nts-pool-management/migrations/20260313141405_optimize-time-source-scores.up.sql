-- Add up migration script here
DROP VIEW time_source_scores;
CREATE VIEW time_source_scores AS SELECT ts.*, 
    COALESCE((SELECT MAX((SELECT score FROM monitor_samples
	    WHERE time_source_id = ts.id AND monitor_id = monitors.id AND protocol = 'ipv4'
	    ORDER BY received_at DESC
	    LIMIT 1)) FROM monitors), 0) AS "ipv4_score",
    COALESCE((SELECT MAX((SELECT score FROM monitor_samples
	    WHERE time_source_id = ts.id AND monitor_id = monitors.id AND protocol = 'ipv6'
	    ORDER BY received_at DESC
	    LIMIT 1)) FROM monitors), 0) AS "ipv6_score",
    COALESCE((SELECT MAX((SELECT score FROM monitor_samples
	    WHERE time_source_id = ts.id AND monitor_id = monitors.id AND protocol = 'srvv4'
	    ORDER BY received_at DESC
	    LIMIT 1)) FROM monitors), 0) AS "srv4_score",
    COALESCE((SELECT MAX((SELECT score FROM monitor_samples
	    WHERE time_source_id = ts.id AND monitor_id = monitors.id AND protocol = 'srvv6'
	    ORDER BY received_at DESC
	    LIMIT 1)) FROM monitors), 0) AS "srv6_score"
FROM time_sources AS ts;
