-- =============================================================================
-- Migration 001: Users Authentication Table, RLS Policies & Auth Sync Trigger
-- Sentinel AI - Supabase Auth (Google OAuth)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Public Users Table (1:1 with auth.users)
-- -----------------------------------------------------------------------------
create table if not exists public.users (
  id uuid primary key references auth.users (id) on delete cascade,
  email text not null unique,
  created_at timestamptz not null default timezone('utc', now()),
  last_login timestamptz not null default timezone('utc', now())
);

create index if not exists idx_users_last_login on public.users (last_login desc);

-- -----------------------------------------------------------------------------
-- 2. Row-Level Security (RLS)
--    Users may only read, insert, and update their own row.
-- -----------------------------------------------------------------------------
alter table public.users enable row level security;

drop policy if exists "users_select_own" on public.users;
create policy "users_select_own"
  on public.users
  for select
  using (auth.uid() = id);

drop policy if exists "users_insert_own" on public.users;
create policy "users_insert_own"
  on public.users
  for insert
  with check (auth.uid() = id);

drop policy if exists "users_update_own" on public.users;
create policy "users_update_own"
  on public.users
  for update
  using (auth.uid() = id)
  with check (auth.uid() = id);

-- -----------------------------------------------------------------------------
-- 3. Trigger on auth.users (INSERT / UPDATE) to sync id, email, created_at,
--    and last_login into public.users automatically.
-- -----------------------------------------------------------------------------
create or replace function public.sync_auth_user_to_public_users()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  resolved_email text;
  resolved_created_at timestamptz;
  resolved_last_login timestamptz;
begin
  resolved_email := coalesce(new.email, '');
  resolved_created_at := coalesce(new.created_at, timezone('utc', now()));
  resolved_last_login := coalesce(new.last_sign_in_at, timezone('utc', now()));

  insert into public.users (id, email, created_at, last_login)
  values (new.id, resolved_email, resolved_created_at, resolved_last_login)
  on conflict (id) do update
  set
    email = excluded.email,
    last_login = greatest(public.users.last_login, excluded.last_login);

  return new;
end;
$$;

drop trigger if exists trg_auth_users_sync_insert on auth.users;
create trigger trg_auth_users_sync_insert
  after insert on auth.users
  for each row execute function public.sync_auth_user_to_public_users();

drop trigger if exists trg_auth_users_sync_update on auth.users;
create trigger trg_auth_users_sync_update
  after update of email, last_sign_in_at on auth.users
  for each row execute function public.sync_auth_user_to_public_users();

-- -----------------------------------------------------------------------------
-- 4. Backfill any existing auth.users rows idempotently
-- -----------------------------------------------------------------------------
insert into public.users (id, email, created_at, last_login)
select
  au.id,
  coalesce(au.email, ''),
  coalesce(au.created_at, timezone('utc', now())),
  coalesce(au.last_sign_in_at, au.created_at, timezone('utc', now()))
from auth.users as au
where au.email is not null
on conflict (id) do nothing;
