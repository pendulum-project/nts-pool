-- Add down migration script here
DROP INDEX time_sources_hostname_port_unique;
ALTER TABLE time_sources ALTER COLUMN port DROP NOT NULL;
ALTER TABLE time_sources ALTER COLUMN port DROP DEFAULT;
