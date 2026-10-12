-- Managed runtime roles may use existing objects only. Schema migration and
-- backup identities remain separate cluster-owner duties.

DO $$
DECLARE
  role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY[
    'vigil_app', 'vigil_agent', 'vigil_security', 'vigil_connector', 'vigil_reasoner'
  ]
  LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
      EXECUTE format(
        'ALTER ROLE %I NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS',
        role_name
      );
      EXECUTE format('ALTER ROLE %I SET search_path = pg_catalog, public', role_name);
      EXECUTE format('REVOKE CREATE ON SCHEMA public FROM %I', role_name);
      EXECUTE format('REVOKE TRUNCATE, REFERENCES, TRIGGER ON ALL TABLES IN SCHEMA public FROM %I', role_name);
      EXECUTE format('REVOKE CREATE, TEMPORARY ON DATABASE %I FROM %I', current_database(), role_name);
    END IF;
  END LOOP;
END
$$;

-- PostgreSQL grants schema/database creation to PUBLIC on some versions. A
-- runtime identity added later must receive an explicit grant rather than
-- inheriting an object-creation path from PUBLIC.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
DO $$
BEGIN
  EXECUTE format('REVOKE CREATE, TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
END
$$;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
  REVOKE TRUNCATE, REFERENCES, TRIGGER ON TABLES FROM PUBLIC;
