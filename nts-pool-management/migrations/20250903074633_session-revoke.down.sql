-- Add down migration script here
ALTER TABLE users DROP COLUMN session_revoke_token;
