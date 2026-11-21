-- =============================================================================
-- Migration 003: Complete Production Schema (10 Core Tables + Backwards Compat)
-- Sentinel AI - Incremental Idempotent Migration
--
-- Creates:
--   - public.projects
--   - public.fixes
--   - public.reports
--   - public.timeline
--   - public.security_scores
--
-- Extends existing tables idempotently:
--   - public.users (full_name, avatar_url, role, updated_at + auth sync trigger)
--   - public.scans (project_id FK -> public.projects)
--   - public.vulnerabilities (project_id FK -> public.projects, risk)
--   - public.attack_simulations (project_id FK, attack_type, attack_payload,
--       before_result, after_result, success, blocked, animation_data)
--   - public.audit_logs (ip_address, user_agent)
--   - public.security_timeline (optional project_id FK for backwards compat)
--
-- Preserves public.profiles, public.custom_rules, public.security_reports,
-- and public.security_timeline for full backwards compatibility.
-- =============================================================================

create extension if not exists "pgcrypto";

-- -----------------------------------------------------------------------------
-- 0. Shared utility trigger: keep `updated_at` current on every row update
-- -----------------------------------------------------------------------------
create or replace function public.handle_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = timezone('utc', now());
  return new;
end;
$$;

-- -----------------------------------------------------------------------------
-- 1. Extend public.users (created in Migration 001)
-- -----------------------------------------------------------------------------
create table if not exists public.users (
  id uuid primary key references auth.users (id) on delete cascade,
  email text not null unique,
  full_name text,
  avatar_url text,
  role text not null default 'user' check (role in ('user', 'admin')),
  created_at timestamptz not null default timezone('utc', now()),
  last_login timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now())
);

alter table public.users add column if not exists full_name text;
alter table public.users add column if not exists avatar_url text;
alter table public.users add column if not exists role text not null default 'user';
alter table public.users add column if not exists updated_at timestamptz not null default timezone('utc', now());

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'chk_users_role' and conrelid = 'public.users'::regclass
  ) then
    alter table public.users
      add constraint chk_users_role check (role in ('user', 'admin'));
  end if;
end $$;

drop trigger if exists trg_users_updated_at on public.users;
create trigger trg_users_updated_at
  before update on public.users
  for each row execute function public.handle_updated_at();

-- Update auth.users sync function to keep full_name, avatar_url, updated_at synced
create or replace function public.sync_auth_user_to_public_users()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  resolved_email text;
  resolved_full_name text;
  resolved_avatar_url text;
  resolved_created_at timestamptz;
  resolved_last_login timestamptz;
begin
  resolved_email := coalesce(new.email, '');
  resolved_full_name := coalesce(
    new.raw_user_meta_data ->> 'full_name',
    new.raw_user_meta_data ->> 'name'
  );
  resolved_avatar_url := new.raw_user_meta_data ->> 'avatar_url';
  resolved_created_at := coalesce(new.created_at, timezone('utc', now()));
  resolved_last_login := coalesce(new.last_sign_in_at, timezone('utc', now()));

  insert into public.users (
    id, email, full_name, avatar_url, created_at, last_login, updated_at
  )
  values (
    new.id,
    resolved_email,
    resolved_full_name,
    resolved_avatar_url,
    resolved_created_at,
    resolved_last_login,
    timezone('utc', now())
  )
  on conflict (id) do update
  set
    email = excluded.email,
    full_name = coalesce(excluded.full_name, public.users.full_name),
    avatar_url = coalesce(excluded.avatar_url, public.users.avatar_url),
    last_login = greatest(public.users.last_login, excluded.last_login),
    updated_at = timezone('utc', now());

  return new;
end;
$$;

drop trigger if exists trg_auth_users_sync_insert on auth.users;
create trigger trg_auth_users_sync_insert
  after insert on auth.users
  for each row execute function public.sync_auth_user_to_public_users();

drop trigger if exists trg_auth_users_sync_update on auth.users;
create trigger trg_auth_users_sync_update
  after update of email, last_sign_in_at, raw_user_meta_data on auth.users
  for each row execute function public.sync_auth_user_to_public_users();

-- Backfill profile metadata into public.users if profiles table exists
do $$
begin
  if to_regclass('public.profiles') is not null then
    update public.users as u
    set
      full_name = coalesce(u.full_name, p.full_name),
      avatar_url = coalesce(u.avatar_url, p.avatar_url),
      role = coalesce(p.role, u.role)
    from public.profiles as p
    where u.id = p.id;
  end if;
end $$;

-- -----------------------------------------------------------------------------
-- 2. Projects Table (public.projects)
-- -----------------------------------------------------------------------------
create table if not exists public.projects (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users (id) on delete cascade,
  name text not null,
  slug text not null,
  description text,
  repository_url text,
  primary_language text not null default 'typescript',
  latest_security_score integer not null default 100
    check (latest_security_score between 0 and 100),
  risk_level text not null default 'low'
    check (risk_level in ('low', 'medium', 'high', 'critical')),
  status text not null default 'active'
    check (status in ('active', 'archived', 'paused')),
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now()),

  constraint chk_projects_name_non_empty
    check (char_length(trim(name)) > 0),
  constraint chk_projects_slug_non_empty
    check (char_length(trim(slug)) > 0),
  constraint uq_projects_user_slug
    unique (user_id, slug)
);

create index if not exists idx_projects_user_updated
  on public.projects (user_id, updated_at desc);
create index if not exists idx_projects_user_status
  on public.projects (user_id, status);

drop trigger if exists trg_projects_updated_at on public.projects;
create trigger trg_projects_updated_at
  before update on public.projects
  for each row execute function public.handle_updated_at();

-- -----------------------------------------------------------------------------
-- 3. Extend public.scans with project_id FK
-- -----------------------------------------------------------------------------
alter table public.scans
  add column if not exists project_id uuid references public.projects (id) on delete set null;

create index if not exists idx_scans_project_created
  on public.scans (project_id, created_at desc)
  where project_id is not null;

-- -----------------------------------------------------------------------------
-- 4. Extend public.vulnerabilities with project_id FK and risk column
-- -----------------------------------------------------------------------------
alter table public.vulnerabilities
  add column if not exists project_id uuid references public.projects (id) on delete set null;

alter table public.vulnerabilities
  add column if not exists risk text not null default '';

create index if not exists idx_vuln_project_status
  on public.vulnerabilities (project_id, status, severity)
  where project_id is not null;

-- -----------------------------------------------------------------------------
-- 5. Fixes Table (public.fixes)
-- -----------------------------------------------------------------------------
create table if not exists public.fixes (
  id uuid primary key default gen_random_uuid(),
  vulnerability_id uuid not null references public.vulnerabilities (id) on delete cascade,
  scan_id uuid not null references public.scans (id) on delete cascade,
  project_id uuid references public.projects (id) on delete set null,
  user_id uuid not null references auth.users (id) on delete cascade,
  fixer_id text not null,
  original_code text not null,
  secure_code text not null,
  lines_changed jsonb not null default '[]'::jsonb,
  summary text not null default '',
  risk_reduction jsonb not null default '{}'::jsonb,
  applied boolean not null default false,
  applied_at timestamptz,
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now()),

  constraint chk_fixes_applied_timestamp
    check ((applied = false) or (applied_at is not null))
);

create index if not exists idx_fixes_user_created
  on public.fixes (user_id, created_at desc);
create index if not exists idx_fixes_scan
  on public.fixes (scan_id);
create index if not exists idx_fixes_vulnerability
  on public.fixes (vulnerability_id);
create index if not exists idx_fixes_project
  on public.fixes (project_id, created_at desc)
  where project_id is not null;

drop trigger if exists trg_fixes_updated_at on public.fixes;
create trigger trg_fixes_updated_at
  before update on public.fixes
  for each row execute function public.handle_updated_at();

-- Auto-populate applied_at when applied flips to true
create or replace function public.handle_fix_applied_at()
returns trigger
language plpgsql
as $$
begin
  if new.applied = true and new.applied_at is null then
    new.applied_at = timezone('utc', now());
  elsif new.applied = false then
    new.applied_at = null;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_fixes_applied_at on public.fixes;
create trigger trg_fixes_applied_at
  before insert or update of applied, applied_at on public.fixes
  for each row execute function public.handle_fix_applied_at();

-- -----------------------------------------------------------------------------
-- 6. Reports Table (public.reports)
--    (public.security_reports is preserved for backwards compatibility)
-- -----------------------------------------------------------------------------
create table if not exists public.reports (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references public.scans (id) on delete cascade,
  project_id uuid references public.projects (id) on delete set null,
  user_id uuid not null references auth.users (id) on delete cascade,
  title text not null,
  format text not null default 'json'
    check (format in ('json', 'markdown', 'html', 'pdf')),
  risk_level text not null default 'low'
    check (risk_level in ('low', 'medium', 'high', 'critical')),
  security_score integer not null default 100
    check (security_score between 0 and 100),
  report_payload jsonb not null default '{}'::jsonb,
  html_content text,
  pdf_structure jsonb,
  markdown_content text,
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now())
);

create index if not exists idx_reports_canonical_user_created
  on public.reports (user_id, created_at desc);
create index if not exists idx_reports_canonical_scan
  on public.reports (scan_id);
create index if not exists idx_reports_canonical_project
  on public.reports (project_id, created_at desc)
  where project_id is not null;

drop trigger if exists trg_reports_updated_at on public.reports;
create trigger trg_reports_updated_at
  before update on public.reports
  for each row execute function public.handle_updated_at();

-- -----------------------------------------------------------------------------
-- 7. Timeline Table (public.timeline)
--    (public.security_timeline is preserved for backwards compatibility)
-- -----------------------------------------------------------------------------
create table if not exists public.timeline (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  project_id uuid references public.projects (id) on delete set null,
  project_name text not null,
  scan_id uuid references public.scans (id) on delete set null,
  timestamp timestamptz not null default timezone('utc', now()),
  action text not null,
  label text not null,
  description text,
  severity text not null default 'info'
    check (severity in ('critical', 'high', 'medium', 'low', 'info')),
  status text not null default 'completed'
    check (status in ('pending', 'in_progress', 'completed', 'warning', 'blocked', 'approved')),
  metadata jsonb not null default '{}'::jsonb,

  constraint chk_timeline_project_name_non_empty
    check (char_length(trim(project_name)) > 0),
  constraint chk_timeline_label_non_empty
    check (char_length(trim(label)) > 0),
  constraint chk_timeline_action_non_empty
    check (char_length(trim(action)) > 0),
  constraint chk_timeline_metadata_is_object
    check (jsonb_typeof(metadata) = 'object')
);

create index if not exists idx_timeline_user_timestamp_desc
  on public.timeline (user_id, timestamp desc);
create index if not exists idx_timeline_user_project_timestamp
  on public.timeline (user_id, project_id, timestamp asc)
  where project_id is not null;
create index if not exists idx_timeline_user_project_name_timestamp
  on public.timeline (user_id, project_name, timestamp asc);
create index if not exists idx_timeline_user_scan_timestamp
  on public.timeline (user_id, scan_id, timestamp asc)
  where scan_id is not null;

-- Also add optional project_id to legacy public.security_timeline if it exists
do $$
begin
  if to_regclass('public.security_timeline') is not null then
    alter table public.security_timeline
      add column if not exists project_id uuid references public.projects (id) on delete set null;
  end if;
end $$;

-- -----------------------------------------------------------------------------
-- 8. Extend public.attack_simulations
-- -----------------------------------------------------------------------------
alter table public.attack_simulations
  add column if not exists project_id uuid references public.projects (id) on delete set null;
alter table public.attack_simulations
  add column if not exists attack_type text not null default 'exploit_simulation';
alter table public.attack_simulations
  add column if not exists attack_payload text not null default '';
alter table public.attack_simulations
  add column if not exists before_result jsonb not null default '{}'::jsonb;
alter table public.attack_simulations
  add column if not exists after_result jsonb not null default '{}'::jsonb;
alter table public.attack_simulations
  add column if not exists success boolean not null default false;
alter table public.attack_simulations
  add column if not exists blocked boolean not null default true;
alter table public.attack_simulations
  add column if not exists animation_data jsonb not null default '{}'::jsonb;

create index if not exists idx_sim_project_created
  on public.attack_simulations (project_id, created_at desc)
  where project_id is not null;
create index if not exists idx_sim_user_created
  on public.attack_simulations (user_id, created_at desc);

-- -----------------------------------------------------------------------------
-- 9. Security Scores Table (public.security_scores)
-- -----------------------------------------------------------------------------
create table if not exists public.security_scores (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  project_id uuid references public.projects (id) on delete set null,
  scan_id uuid references public.scans (id) on delete cascade,
  score integer not null default 100
    check (score between 0 and 100),
  percentage numeric(5, 2) not null default 100.00
    check (percentage >= 0 and percentage <= 100),
  letter_grade text not null default 'A'
    check (letter_grade in ('A+', 'A', 'B', 'C', 'D', 'F')),
  risk_level text not null default 'low'
    check (risk_level in ('low', 'medium', 'high', 'critical')),
  risk_category text not null default 'secure',
  security_level text not null default 'hardened',
  developer_level text not null default 'guardian',
  critical_issues integer not null default 0 check (critical_issues >= 0),
  high_issues integer not null default 0 check (high_issues >= 0),
  medium_issues integer not null default 0 check (medium_issues >= 0),
  low_issues integer not null default 0 check (low_issues >= 0),
  files_scanned integer not null default 1 check (files_scanned >= 0),
  threats_fixed integer not null default 0 check (threats_fixed >= 0),
  time_saved_minutes integer not null default 0 check (time_saved_minutes >= 0),
  breakdown jsonb not null default '{}'::jsonb,
  calculated_at timestamptz not null default timezone('utc', now()),
  created_at timestamptz not null default timezone('utc', now())
);

create index if not exists idx_security_scores_user_calculated
  on public.security_scores (user_id, calculated_at desc);
create index if not exists idx_security_scores_project_calculated
  on public.security_scores (project_id, calculated_at desc)
  where project_id is not null;
create index if not exists idx_security_scores_scan
  on public.security_scores (scan_id)
  where scan_id is not null;

-- Keep project.latest_security_score & project.risk_level in sync when a new score is recorded
create or replace function public.sync_project_latest_security_score()
returns trigger
language plpgsql
as $$
begin
  if new.project_id is not null then
    update public.projects
    set
      latest_security_score = new.score,
      risk_level = new.risk_level,
      updated_at = timezone('utc', now())
    where id = new.project_id
      and user_id = new.user_id;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_security_scores_sync_project on public.security_scores;
create trigger trg_security_scores_sync_project
  after insert on public.security_scores
  for each row execute function public.sync_project_latest_security_score();

-- -----------------------------------------------------------------------------
-- 10. Extend public.audit_logs with ip_address and user_agent
-- -----------------------------------------------------------------------------
alter table public.audit_logs add column if not exists ip_address text;
alter table public.audit_logs add column if not exists user_agent text;

-- -----------------------------------------------------------------------------
-- 11. Row-Level Security (RLS) Policies for newly created tables
-- -----------------------------------------------------------------------------
alter table public.projects enable row level security;
alter table public.fixes enable row level security;
alter table public.reports enable row level security;
alter table public.timeline enable row level security;
alter table public.security_scores enable row level security;

-- projects
drop policy if exists "projects_select_own" on public.projects;
create policy "projects_select_own"
  on public.projects for select
  using (auth.uid() = user_id);

drop policy if exists "projects_insert_own" on public.projects;
create policy "projects_insert_own"
  on public.projects for insert
  with check (auth.uid() = user_id);

drop policy if exists "projects_update_own" on public.projects;
create policy "projects_update_own"
  on public.projects for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists "projects_delete_own" on public.projects;
create policy "projects_delete_own"
  on public.projects for delete
  using (auth.uid() = user_id);

-- fixes
drop policy if exists "fixes_select_own" on public.fixes;
create policy "fixes_select_own"
  on public.fixes for select
  using (auth.uid() = user_id);

drop policy if exists "fixes_insert_own" on public.fixes;
create policy "fixes_insert_own"
  on public.fixes for insert
  with check (auth.uid() = user_id);

drop policy if exists "fixes_update_own" on public.fixes;
create policy "fixes_update_own"
  on public.fixes for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists "fixes_delete_own" on public.fixes;
create policy "fixes_delete_own"
  on public.fixes for delete
  using (auth.uid() = user_id);

-- reports
drop policy if exists "reports_select_own" on public.reports;
create policy "reports_select_own"
  on public.reports for select
  using (auth.uid() = user_id);

drop policy if exists "reports_insert_own" on public.reports;
create policy "reports_insert_own"
  on public.reports for insert
  with check (auth.uid() = user_id);

drop policy if exists "reports_update_own" on public.reports;
create policy "reports_update_own"
  on public.reports for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists "reports_delete_own" on public.reports;
create policy "reports_delete_own"
  on public.reports for delete
  using (auth.uid() = user_id);

-- timeline
drop policy if exists "timeline_select_own" on public.timeline;
create policy "timeline_select_own"
  on public.timeline for select
  using (auth.uid() = user_id);

drop policy if exists "timeline_insert_own" on public.timeline;
create policy "timeline_insert_own"
  on public.timeline for insert
  with check (auth.uid() = user_id);

drop policy if exists "timeline_update_own" on public.timeline;
create policy "timeline_update_own"
  on public.timeline for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists "timeline_delete_own" on public.timeline;
create policy "timeline_delete_own"
  on public.timeline for delete
  using (auth.uid() = user_id);

-- security_scores
drop policy if exists "security_scores_select_own" on public.security_scores;
create policy "security_scores_select_own"
  on public.security_scores for select
  using (auth.uid() = user_id);

drop policy if exists "security_scores_insert_own" on public.security_scores;
create policy "security_scores_insert_own"
  on public.security_scores for insert
  with check (auth.uid() = user_id);

drop policy if exists "security_scores_update_own" on public.security_scores;
create policy "security_scores_update_own"
  on public.security_scores for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists "security_scores_delete_own" on public.security_scores;
create policy "security_scores_delete_own"
  on public.security_scores for delete
  using (auth.uid() = user_id);
