-- Supabase publishes every table in the "public" schema through its Data API
-- (PostgREST) to the "anon" and "authenticated" roles, using a key that is
-- public by design. Svalinn never uses that API: its server connects to the
-- database directly. So:
--
-- 1. Turn on row-level security for every table, with no policies. The
--    server connects as the tables' owner, which row-level security doesn't
--    apply to; everyone else gets no rows.
-- 2. Remove the Supabase API roles' access to these tables, now and for
--    tables created later.
--
-- On a database without those roles (plain Postgres, Docker), step 2 is
-- skipped and step 1 changes nothing for the server.
--
-- New tables in later migrations should also run:
--   ALTER TABLE <name> ENABLE ROW LEVEL SECURITY;
DO $$
DECLARE
    t record;
    api_role text;
BEGIN
    FOR t IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', t.tablename);
    END LOOP;

    FOREACH api_role IN ARRAY ARRAY['anon', 'authenticated'] LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = api_role) THEN
            EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA public FROM %I', api_role);
            EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM %I', api_role);
            EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM %I', api_role);
            EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM %I', api_role);
            EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM %I', api_role);
            EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM %I', api_role);
        END IF;
    END LOOP;
END $$;
