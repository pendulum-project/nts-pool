-- Add up migration script here
ALTER TABLE time_sources ADD CONSTRAINT weight_positive CHECK (weight > 0);
