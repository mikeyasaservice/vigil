-- Aurora's administrative role is deliberately not a PostgreSQL superuser.
-- Reassert only attributes it is allowed to manage, and fail if a runtime role
-- somehow already owns superuser, replication or RLS-bypass authority.

DO $$
DECLARE
  role_name text;
  role_state record;
BEGIN
  FOREACH role_name IN ARRAY ARRAY[
    'vigil_app', 'vigil_agent', 'vigil_security', 'vigil_connector', 'vigil_reasoner'
  ]
  LOOP
    SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
      INTO role_state
      FROM pg_roles
      WHERE rolname = role_name;

    IF NOT FOUND THEN
      RAISE EXCEPTION 'required managed runtime role % does not exist', role_name;
    END IF;
    IF role_state.rolsuper OR role_state.rolcreatedb OR role_state.rolcreaterole
       OR role_state.rolreplication OR role_state.rolbypassrls THEN
      RAISE EXCEPTION 'managed runtime role % has prohibited authority', role_name;
    END IF;

    EXECUTE format('ALTER ROLE %I NOINHERIT', role_name);
    EXECUTE format('ALTER ROLE %I SET search_path = pg_catalog, public', role_name);
    EXECUTE format('REVOKE CREATE ON SCHEMA public FROM %I', role_name);
    EXECUTE format(
      'REVOKE CREATE, TEMPORARY ON DATABASE %I FROM %I',
      current_database(), role_name
    );
  END LOOP;
END
$$;
