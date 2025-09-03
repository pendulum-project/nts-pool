-- Add up migration script here
ALTER TABLE users ADD COLUMN session_revoke_token TEXT NOT NULL DEFAULT '';
