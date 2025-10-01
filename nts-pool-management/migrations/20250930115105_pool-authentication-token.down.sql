-- Add down migration script here
ALTER TABLE time_sources DROP COLUMN auth_token_randomizer;
ALTER TABLE time_sources DROP COLUMN base_secret_index;
