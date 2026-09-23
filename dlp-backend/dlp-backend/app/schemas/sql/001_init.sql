-- DLP initial schema. Run in Supabase SQL editor.
-- Mirrors app/models/finding.py and app/models/policy.py — keep in sync.

create table if not exists dlp_events (
    id uuid primary key default gen_random_uuid(),
    org_id uuid not null,
    user_id uuid not null,
    channel text not null,
    data_type text not null,
    confidence float not null,
    destination text not null,
    decision text not null,
    snippet text not null,
    created_at timestamptz not null default now()
);

create table if not exists dlp_policies (
    id uuid primary key default gen_random_uuid(),
    org_id uuid not null,
    data_type text not null,
    channel text not null,
    condition jsonb not null default '{}'::jsonb,
    action text not null,
    is_exception boolean not null default false,
    created_at timestamptz not null default now()
);

create table if not exists dlp_classifications (
    id uuid primary key default gen_random_uuid(),
    org_id uuid not null,
    label text not null,
    pattern_type text not null,   -- regex | edm | fingerprint
    pattern_value text not null,
    sensitivity_level text not null default 'internal',
    created_at timestamptz not null default now()
);

create table if not exists dlp_exceptions (
    id uuid primary key default gen_random_uuid(),
    org_id uuid not null,
    destination_or_user text not null,
    reason text not null,
    approved_by text not null,
    expires_at timestamptz,
    created_at timestamptz not null default now()
);

create table if not exists dlp_channels (
    id uuid primary key default gen_random_uuid(),
    org_id uuid not null,
    channel_type text not null,   -- gmail | drive | browser
    config jsonb not null default '{}'::jsonb,
    connected_at timestamptz not null default now()
);

-- RLS: org-scoped access, same convention as SecureFlow's projects/scans/findings.
-- Assumes an org_members(org_id, user_id) table exists for membership checks —
-- create one first if this project doesn't already have it.

alter table dlp_events enable row level security;
alter table dlp_policies enable row level security;
alter table dlp_classifications enable row level security;
alter table dlp_exceptions enable row level security;
alter table dlp_channels enable row level security;

create policy "org members can read events" on dlp_events
    for select using (org_id in (select org_id from org_members where user_id = auth.uid()));

create policy "org members can read policies" on dlp_policies
    for select using (org_id in (select org_id from org_members where user_id = auth.uid()));

create policy "org members can manage policies" on dlp_policies
    for all using (org_id in (select org_id from org_members where user_id = auth.uid()));

create policy "org members can read classifications" on dlp_classifications
    for select using (org_id in (select org_id from org_members where user_id = auth.uid()));

create policy "org members can read exceptions" on dlp_exceptions
    for select using (org_id in (select org_id from org_members where user_id = auth.uid()));

create policy "org members can read channels" on dlp_channels
    for select using (org_id in (select org_id from org_members where user_id = auth.uid()));
