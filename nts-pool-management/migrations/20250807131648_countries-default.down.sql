-- Add down migration script here
ALTER TABLE time_sources ALTER COLUMN countries DROP DEFAULT;
