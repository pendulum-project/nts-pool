-- Add down migration script here
ALTER TABLE users DROP COLUMN activation_token;
ALTER TABLE users DROP COLUMN activation_expires_at;
ALTER TABLE users DROP COLUMN activated_since;
ALTER TABLE users DROP COLUMN last_login_at;
ALTER TABLE users DROP COLUMN disabled_since;
