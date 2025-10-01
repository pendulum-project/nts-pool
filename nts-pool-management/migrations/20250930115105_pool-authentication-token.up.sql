-- Add up migration script here
ALTER TABLE time_sources ADD COLUMN auth_token_randomizer TEXT NOT NULL DEFAULT '';
ALTER TABLE time_sources ADD COLUMN base_secret_index INTEGER NOT NULL DEFAULT 0;
