-- Add up migration script here
ALTER TABLE time_sources ALTER COLUMN countries SET DEFAULT array[]::varchar[];
