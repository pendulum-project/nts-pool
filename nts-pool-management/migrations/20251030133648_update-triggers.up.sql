CREATE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at := now();
   RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_set_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER authentication_methods_set_updated_at
BEFORE UPDATE ON authentication_methods
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER monitors_set_updated_at
BEFORE UPDATE ON monitors
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER time_sources_set_updated_at
BEFORE UPDATE ON time_sources
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
