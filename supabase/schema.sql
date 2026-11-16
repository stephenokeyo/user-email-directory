create table if not exists public.directory_members (
  email text primary key check (email = lower(btrim(email))),
  created_at timestamptz not null default now()
);

create table if not exists public.directory_records (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(btrim(name)) between 1 and 120),
  email text not null check (char_length(btrim(email)) between 1 and 254),
  access_ref text not null default '' check (char_length(access_ref) <= 80),
  vault_url text not null default '' check (
    char_length(vault_url) <= 2048 and
    (vault_url = '' or (
      vault_url like 'https://%' and
      position('?' in vault_url) = 0 and
      position('#' in vault_url) = 0
    ))
  ),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index if not exists directory_records_email_lower_uidx
  on public.directory_records (lower(email));

alter table public.directory_members enable row level security;
alter table public.directory_records enable row level security;

revoke all on public.directory_members from public, anon, authenticated;
revoke all on public.directory_records from public, anon, authenticated;
grant usage on schema public to authenticated;
grant select on public.directory_members to authenticated;
grant select, insert, update, delete on public.directory_records to authenticated;

create or replace function public.is_directory_member()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.directory_members as member
    where member.email = lower(coalesce(auth.jwt() ->> 'email', ''))
  );
$$;

revoke all on function public.is_directory_member() from public, anon;
grant execute on function public.is_directory_member() to authenticated;

drop policy if exists "Members can read their own membership" on public.directory_members;
create policy "Members can read their own membership"
  on public.directory_members
  for select
  to authenticated
  using (email = lower(coalesce(auth.jwt() ->> 'email', '')));

drop policy if exists "Directory members can read records" on public.directory_records;
create policy "Directory members can read records"
  on public.directory_records
  for select
  to authenticated
  using (public.is_directory_member());

drop policy if exists "Directory members can create records" on public.directory_records;
create policy "Directory members can create records"
  on public.directory_records
  for insert
  to authenticated
  with check (public.is_directory_member());

drop policy if exists "Directory members can update records" on public.directory_records;
create policy "Directory members can update records"
  on public.directory_records
  for update
  to authenticated
  using (public.is_directory_member())
  with check (public.is_directory_member());

drop policy if exists "Directory members can delete records" on public.directory_records;
create policy "Directory members can delete records"
  on public.directory_records
  for delete
  to authenticated
  using (public.is_directory_member());

create or replace function public.set_directory_record_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists set_directory_record_updated_at on public.directory_records;
create trigger set_directory_record_updated_at
  before update on public.directory_records
  for each row
  execute function public.set_directory_record_updated_at();
