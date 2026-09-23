-- Organizations
CREATE TABLE public.organizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE public.org_members (
  org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL,
  role TEXT NOT NULL DEFAULT 'member',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, user_id)
);

CREATE TABLE public.dlp_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  user_id UUID,
  channel TEXT NOT NULL,
  data_type TEXT NOT NULL,
  confidence NUMERIC NOT NULL DEFAULT 0,
  destination TEXT,
  decision TEXT NOT NULL,
  snippet TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE public.dlp_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  data_type TEXT NOT NULL,
  channel TEXT NOT NULL,
  condition JSONB NOT NULL DEFAULT '{}'::jsonb,
  action TEXT NOT NULL,
  is_exception BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE public.dlp_classifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  pattern_type TEXT NOT NULL,
  pattern_value TEXT NOT NULL,
  sensitivity_level INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE public.dlp_exceptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  destination_or_user TEXT NOT NULL,
  reason TEXT NOT NULL,
  approved_by TEXT,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE public.dlp_channels (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  channel_type TEXT NOT NULL,
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  connected_at TIMESTAMPTZ
);

CREATE INDEX idx_dlp_events_org_created ON public.dlp_events(org_id, created_at DESC);
CREATE INDEX idx_dlp_policies_org ON public.dlp_policies(org_id);
CREATE INDEX idx_dlp_exceptions_org ON public.dlp_exceptions(org_id);

-- Grants
GRANT SELECT, INSERT, UPDATE, DELETE ON public.organizations TO authenticated;
GRANT ALL ON public.organizations TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.org_members TO authenticated;
GRANT ALL ON public.org_members TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.dlp_events TO authenticated;
GRANT ALL ON public.dlp_events TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.dlp_policies TO authenticated;
GRANT ALL ON public.dlp_policies TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.dlp_classifications TO authenticated;
GRANT ALL ON public.dlp_classifications TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.dlp_exceptions TO authenticated;
GRANT ALL ON public.dlp_exceptions TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.dlp_channels TO authenticated;
GRANT ALL ON public.dlp_channels TO service_role;

-- Membership helper (security definer avoids recursive RLS)
CREATE OR REPLACE FUNCTION public.is_org_member(_org_id UUID, _user_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.org_members
    WHERE org_id = _org_id AND user_id = _user_id
  )
$$;

ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.org_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dlp_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dlp_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dlp_classifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dlp_exceptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dlp_channels ENABLE ROW LEVEL SECURITY;

CREATE POLICY "members read org" ON public.organizations
  FOR SELECT TO authenticated USING (public.is_org_member(id, auth.uid()));

CREATE POLICY "read own membership" ON public.org_members
  FOR SELECT TO authenticated USING (user_id = auth.uid() OR public.is_org_member(org_id, auth.uid()));

-- Generic org-scoped policies
CREATE POLICY "org members full access" ON public.dlp_events
  FOR ALL TO authenticated
  USING (public.is_org_member(org_id, auth.uid()))
  WITH CHECK (public.is_org_member(org_id, auth.uid()));

CREATE POLICY "org members full access" ON public.dlp_policies
  FOR ALL TO authenticated
  USING (public.is_org_member(org_id, auth.uid()))
  WITH CHECK (public.is_org_member(org_id, auth.uid()));

CREATE POLICY "org members full access" ON public.dlp_classifications
  FOR ALL TO authenticated
  USING (public.is_org_member(org_id, auth.uid()))
  WITH CHECK (public.is_org_member(org_id, auth.uid()));

CREATE POLICY "org members full access" ON public.dlp_exceptions
  FOR ALL TO authenticated
  USING (public.is_org_member(org_id, auth.uid()))
  WITH CHECK (public.is_org_member(org_id, auth.uid()));

CREATE POLICY "org members full access" ON public.dlp_channels
  FOR ALL TO authenticated
  USING (public.is_org_member(org_id, auth.uid()))
  WITH CHECK (public.is_org_member(org_id, auth.uid()));

-- Provision an org for the current user on first sign-in
CREATE OR REPLACE FUNCTION public.ensure_org()
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  _uid UUID := auth.uid();
  _org UUID;
BEGIN
  IF _uid IS NULL THEN
    RAISE EXCEPTION 'not authenticated';
  END IF;

  SELECT org_id INTO _org FROM public.org_members WHERE user_id = _uid LIMIT 1;
  IF _org IS NOT NULL THEN
    RETURN _org;
  END IF;

  INSERT INTO public.organizations (name) VALUES ('My Organization') RETURNING id INTO _org;
  INSERT INTO public.org_members (org_id, user_id, role) VALUES (_org, _uid, 'owner');

  INSERT INTO public.dlp_channels (org_id, channel_type, config, connected_at)
  VALUES (_org, 'gmail', '{}'::jsonb, NULL),
         (_org, 'drive', '{}'::jsonb, NULL),
         (_org, 'browser', '{}'::jsonb, NULL);

  RETURN _org;
END;
$$;

GRANT EXECUTE ON FUNCTION public.ensure_org() TO authenticated;