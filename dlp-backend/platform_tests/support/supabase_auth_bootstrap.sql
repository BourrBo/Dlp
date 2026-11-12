-- Minimal Supabase Auth compatibility surface for the local PostgreSQL RLS test.
-- PostgreSQL itself enforces all policies; this matches Supabase auth.jwt() by
-- exposing transaction-local verified request.jwt.claims as jsonb.
CREATE ROLE authenticated NOLOGIN;
CREATE SCHEMA auth;
CREATE OR REPLACE FUNCTION auth.jwt()
RETURNS jsonb
LANGUAGE sql
STABLE
AS $$ SELECT NULLIF(current_setting('request.jwt.claims', true), '')::jsonb $$;
GRANT USAGE ON SCHEMA auth TO authenticated;
GRANT EXECUTE ON FUNCTION auth.jwt() TO authenticated;
GRANT USAGE ON SCHEMA public TO authenticated;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT ALL ON TABLES TO authenticated;
