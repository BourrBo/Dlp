-- Person B detection support. Run after the dashboard's 0000 schema migration.
-- Current dashboard schema uses a numeric sensitivity_level; detection uses
-- readable labels, so map existing levels before adding hashed rules.
alter table public.dlp_classifications
    alter column sensitivity_level type text using
      case sensitivity_level::text
        when '0' then 'public'
        when '1' then 'internal'
        when '2' then 'confidential'
        when '3' then 'restricted'
        else sensitivity_level::text
      end,
    alter column sensitivity_level set default 'internal';

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'dlp_classifications_pattern_type_check'
      and conrelid = 'public.dlp_classifications'::regclass
  ) then
    alter table public.dlp_classifications
      add constraint dlp_classifications_pattern_type_check
      check (pattern_type in ('regex', 'edm', 'fingerprint')) not valid;
  end if;
end $$;

create index if not exists idx_dlp_classifications_org_type
  on public.dlp_classifications (org_id, pattern_type);

drop policy if exists "org members can manage classifications"
  on public.dlp_classifications;
create policy "org members can manage classifications"
  on public.dlp_classifications for all to authenticated
  using (public.is_org_member(org_id, auth.uid()))
  with check (public.is_org_member(org_id, auth.uid()));

-- Rules are scoped to regex, EDM, and fingerprint detectors. EDM pattern_value
-- is SHA-256(normalized value); never store the original value there.
