-- Runs once, when the platform-db volume is first created.
-- The platform's row-level-security migrations expect Supabase's `authenticated`
-- role and `auth.jwt()`; plain PostgreSQL has neither, so provide them.
-- Policies are still enforced by PostgreSQL itself.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        CREATE ROLE authenticated NOLOGIN;
    END IF;
END $$;
CREATE SCHEMA IF NOT EXISTS auth;
CREATE OR REPLACE FUNCTION auth.jwt()
RETURNS jsonb
LANGUAGE sql
STABLE
AS $$ SELECT NULLIF(current_setting('request.jwt.claims', true), '')::jsonb $$;
GRANT USAGE ON SCHEMA auth TO authenticated;
GRANT EXECUTE ON FUNCTION auth.jwt() TO authenticated;
GRANT USAGE ON SCHEMA public TO authenticated;
-- Applies to tables later created by the role that runs this script (the migration owner).
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO authenticated;
