-- Add up migration script here
UPDATE time_sources SET port=4460 WHERE port IS NULL;
ALTER TABLE time_sources ALTER COLUMN port SET DEFAULT 4460;
ALTER TABLE time_sources ALTER COLUMN port SET NOT NULL;
CREATE UNIQUE INDEX time_sources_hostname_port_unique ON time_sources (hostname, port) WHERE NOT deleted;
