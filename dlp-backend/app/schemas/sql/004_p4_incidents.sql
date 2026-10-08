-- Incident records and their timeline. Store metadata only; never raw sensitive evidence.
create table if not exists public.dlp_incidents (
    id uuid primary key default gen_random_uuid(),
    org_id uuid not null,
    number text not null check (number ~ '^INC-[0-9]{4}$'),
    title text not null,
    severity text not null,
    status text not null default 'open'
        check (status in ('open', 'triaged', 'fixed', 'accepted', 'false_positive')),
    assignee text,
    source text not null,
    policy_id uuid,
    data_type text not null,
    first_seen timestamptz not null,
    last_seen timestamptz not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table if not exists public.dlp_incident_events (
    id uuid primary key default gen_random_uuid(),
    incident_id uuid not null references public.dlp_incidents (id),
    org_id uuid not null,
    event_type text not null,
    actor text,
    comment text,
    created_at timestamptz not null default now()
);

create index if not exists idx_dlp_incidents_org_id
    on public.dlp_incidents (org_id);
create index if not exists idx_dlp_incidents_number
    on public.dlp_incidents (number);
create index if not exists idx_dlp_incidents_status
    on public.dlp_incidents (status);
create index if not exists idx_dlp_incidents_created_at
    on public.dlp_incidents (created_at);
create index if not exists idx_dlp_incident_events_org_id
    on public.dlp_incident_events (org_id);
create index if not exists idx_dlp_incident_events_incident_id
    on public.dlp_incident_events (incident_id);
create index if not exists idx_dlp_incident_events_created_at
    on public.dlp_incident_events (created_at);

grant select, insert, update, delete on public.dlp_incidents to authenticated;
grant all on public.dlp_incidents to service_role;
grant select, insert, update, delete on public.dlp_incident_events to authenticated;
grant all on public.dlp_incident_events to service_role;

alter table public.dlp_incidents enable row level security;
alter table public.dlp_incident_events enable row level security;

drop policy if exists "org members full access" on public.dlp_incidents;
create policy "org members full access" on public.dlp_incidents
    for all to authenticated
    using (public.is_org_member(org_id, auth.uid()))
    with check (public.is_org_member(org_id, auth.uid()));

drop policy if exists "org members full access" on public.dlp_incident_events;
create policy "org members full access" on public.dlp_incident_events
    for all to authenticated
    using (public.is_org_member(org_id, auth.uid()))
    with check (public.is_org_member(org_id, auth.uid()));
