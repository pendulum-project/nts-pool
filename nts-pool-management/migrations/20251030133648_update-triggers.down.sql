-- Add down migration script here
DROP TRIGGER time_sources_set_updated_at ON time_sources;
DROP TRIGGER monitors_set_updated_at ON monitors;
DROP TRIGGER authentication_methods_set_updated_at ON authentication_methods;
DROP TRIGGER users_set_updated_at ON users;

DROP FUNCTION set_updated_at();
