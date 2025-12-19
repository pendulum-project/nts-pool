-- Add down migration script here
ALTER TABLE time_sources DROP CONSTRAINT weight_positive;
