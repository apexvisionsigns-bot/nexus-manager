-- Run this ONCE in Supabase: SQL Editor -> New query -> paste -> Run

create table if not exists nx_users (
  email text primary key,
  name text not null default '',
  role text not null default 'staff',
  salt text not null,
  hash text not null,
  created_at timestamptz not null default now()
);

create table if not exists nx_records (
  id text primary key,
  kind text not null,
  data jsonb not null default '{}',
  deleted boolean not null default false,
  updated_at timestamptz not null default clock_timestamp()
);

create index if not exists nx_records_upd on nx_records (updated_at, id);

-- always stamp updated_at on the server
create or replace function nx_touch() returns trigger language plpgsql as $$
begin
  new.updated_at := clock_timestamp();
  return new;
end $$;

drop trigger if exists nx_records_touch on nx_records;
create trigger nx_records_touch before insert or update on nx_records
  for each row execute function nx_touch();

-- keyset pagination used by the sync (pull)
create or replace function nx_pull(p_since timestamptz, p_after text, p_kinds text[], p_limit int)
returns table (id text, kind text, data jsonb, deleted boolean, updated_at timestamptz)
language sql stable as $$
  select r.id, r.kind, r.data, r.deleted, r.updated_at
  from nx_records r
  where (r.updated_at, r.id) > (p_since, p_after)
    and (p_kinds is null or r.kind = any(p_kinds))
  order by r.updated_at, r.id
  limit p_limit
$$;

-- lock everything: only the server (service_role key) can touch the data
alter table nx_users enable row level security;
alter table nx_records enable row level security;
revoke all on nx_users, nx_records from anon, authenticated;
revoke all on function nx_pull(timestamptz, text, text[], int) from public, anon, authenticated;
grant execute on function nx_pull(timestamptz, text, text[], int) to service_role;
