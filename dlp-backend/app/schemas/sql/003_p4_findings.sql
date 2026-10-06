-- Persisted finding records for the P4 findings workflow.
create table if not exists public.dlp_findings (
    id uuid primary key default gen_random_uuid(),
    org_id uuid not null,
    user_id uuid not null,
    event_id uuid,
    severity text not null,
    classification text,
    data_type text not null,
    status text not null default 'open'
        check (status in ('open', 'triaged', 'fixed', 'accepted', 'false_positive')),
    source text not null,
    detector text,
    confidence float not null,
    destination text,
    masked_evidence text,
    location text,
    policy_id uuid,
    decision text,
    fingerprint text,
    owner text,
    notes text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists idx_dlp_findings_org_id
    on public.dlp_findings (org_id);
create index if not exists idx_dlp_findings_created_at
    on public.dlp_findings (created_at);
create index if not exists idx_dlp_findings_status
    on public.dlp_findings (status);
create index if not exists idx_dlp_findings_severity
    on public.dlp_findings (severity);
create index if not exists idx_dlp_findings_classification
    on public.dlp_findings (classification);
create index if not exists idx_dlp_findings_data_type
    on public.dlp_findings (data_type);
create index if not exists idx_dlp_findings_source
    on public.dlp_findings (source);

grant select, insert, update, delete on public.dlp_findings to authenticated;
grant all on public.dlp_findings to service_role;

alter table public.dlp_findings enable row level security;

drop policy if exists "org members full access" on public.dlp_findings;
create policy "org members full access" on public.dlp_findings
    for all to authenticated
    using (public.is_org_member(org_id, auth.uid()))
    with check (public.is_org_member(org_id, auth.uid()));
