-- Approved fingerprints served to the offline CLI via GET /api/v1/allowlist.
create table if not exists public.dlp_allowlist (
    id uuid primary key default gen_random_uuid(),
    org_id uuid not null references public.organizations(id) on delete cascade,
    fingerprint text not null check (fingerprint ~ '^[0-9a-f]{16}$'),
    reason text,
    created_by uuid,
    created_at timestamptz not null default now(),
    unique (org_id, fingerprint)
);

grant select, insert, delete on public.dlp_allowlist to authenticated;
grant all on public.dlp_allowlist to service_role;

alter table public.dlp_allowlist enable row level security;

drop policy if exists "org members full access" on public.dlp_allowlist;
create policy "org members full access" on public.dlp_allowlist
    for all to authenticated
    using (public.is_org_member(org_id, auth.uid()))
    with check (public.is_org_member(org_id, auth.uid()));
