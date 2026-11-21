-- =============================================================================
-- Sentinel AI - Complete Canonical Production Supabase PostgreSQL Schema
-- Self-contained schema for fresh Supabase deployments.
-- Run this in the Supabase SQL Editor or via Supabase CLI.
--
-- Core Tables (10):
--   1.  public.users
--   2.  public.projects
--   3.  public.scans
--   4.  public.vulnerabilities
--   5.  public.fixes
--   6.  public.reports
--   7.  public.timeline
--   8.  public.attack_simulations
--   9.  public.security_scores
--   10. public.audit_logs
--
-- Backwards-Compatible Tables:
--   11. public.profiles
--   12. public.custom_rules
--   13. public.security_reports
--   14. public.security_timeline
-- =============================================================================

create extension if not exists "pgcrypto";

-- -----------------------------------------------------------------------------
-- Utility trigger: keep `updated_at` current on every row update
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
-- 1. Public Users (1:1 with auth.users / Google OAuth)
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

create index if not exists idx_users_last_login
  on public.users (last_login desc);

drop trigger if exists trg_users_updated_at on public.users;
create trigger trg_users_updated_at
  before update on public.users
  for each row execute function public.handle_updated_at();

-- Automatically sync auth.users inserts/updates into public.users
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

-- -----------------------------------------------------------------------------
-- 2. Projects
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
create index if not exists idx_projects_active_leaderboard
  on public.projects (user_id, latest_security_score desc, updated_at desc)
  where status = 'active';
create index if not exists idx_projects_user_risk_level
  on public.projects (user_id, risk_level, updated_at desc);

drop trigger if exists trg_projects_updated_at on public.projects;
create trigger trg_projects_updated_at
  before update on public.projects
  for each row execute function public.handle_updated_at();

-- -----------------------------------------------------------------------------
-- 3. Code Scans
-- -----------------------------------------------------------------------------
create table if not exists public.scans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  project_id uuid references public.projects (id) on delete set null,
  project_name text not null default 'Untitled Project',
  file_name text not null default 'snippet.ts',
  language text not null default 'unknown',
  source_code text not null,
  code_hash text not null,
  ai_model_source text,
  status text not null default 'completed'
    check (status in ('pending', 'processing', 'completed', 'failed')),
  risk_score integer not null default 0 check (risk_score between 0 and 100),
  risk_grade text not null default 'A' check (risk_grade in ('A', 'B', 'C', 'D', 'F')),
  summary text not null default '',
  severity_breakdown jsonb not null default '{"critical":0,"high":0,"medium":0,"low":0,"info":0}'::jsonb,
  executed_rules_count integer not null default 0,
  duration_ms integer not null default 0,
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now())
);

create index if not exists idx_scans_user_created
  on public.scans (user_id, created_at desc);
create index if not exists idx_scans_code_hash
  on public.scans (user_id, code_hash);
create index if not exists idx_scans_project_created
  on public.scans (project_id, created_at desc)
  where project_id is not null;
create index if not exists idx_scans_user_status_created
  on public.scans (user_id, status, created_at desc);
create index if not exists idx_scans_user_project_created
  on public.scans (user_id, project_id, created_at desc)
  where project_id is not null;

drop trigger if exists trg_scans_updated_at on public.scans;
create trigger trg_scans_updated_at
  before update on public.scans
  for each row execute function public.handle_updated_at();

-- -----------------------------------------------------------------------------
-- 4. Detected Vulnerabilities
-- -----------------------------------------------------------------------------
create table if not exists public.vulnerabilities (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references public.scans (id) on delete cascade,
  project_id uuid references public.projects (id) on delete set null,
  user_id uuid not null references auth.users (id) on delete cascade,
  rule_id text not null,
  title text not null,
  description text not null,
  explanation text not null,
  risk text not null default '',
  severity text not null check (severity in ('critical', 'high', 'medium', 'low', 'info')),
  category text not null,
  cwe_id text not null,
  owasp_category text not null,
  confidence numeric(4, 3) not null default 0.850 check (confidence >= 0 and confidence <= 1),
  line_start integer not null,
  column_start integer not null,
  line_end integer not null,
  column_end integer not null,
  code_snippet text not null,
  matched_text text not null,
  remediation jsonb not null,
  status text not null default 'open'
    check (status in ('open', 'acknowledged', 'fixed', 'false_positive')),
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now())
);

create index if not exists idx_vuln_scan
  on public.vulnerabilities (scan_id);
create index if not exists idx_vuln_user_severity
  on public.vulnerabilities (user_id, severity);
create index if not exists idx_vuln_project_status
  on public.vulnerabilities (project_id, status, severity)
  where project_id is not null;
create index if not exists idx_vuln_user_status_severity_created
  on public.vulnerabilities (user_id, status, severity, created_at desc);
create index if not exists idx_vuln_open_critical_high
  on public.vulnerabilities (user_id, project_id, created_at desc)
  where status = 'open' and severity in ('critical', 'high');
create index if not exists idx_vuln_user_created
  on public.vulnerabilities (user_id, created_at desc);

drop trigger if exists trg_vulnerabilities_updated_at on public.vulnerabilities;
create trigger trg_vulnerabilities_updated_at
  before update on public.vulnerabilities
  for each row execute function public.handle_updated_at();

-- -----------------------------------------------------------------------------
-- 5. Automated Security Fixes
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
create index if not exists idx_fixes_user_applied_at
  on public.fixes (user_id, applied_at desc)
  where applied = true;
create index if not exists idx_fixes_user_project_applied
  on public.fixes (user_id, project_id, applied)
  where project_id is not null;

drop trigger if exists trg_fixes_updated_at on public.fixes;
create trigger trg_fixes_updated_at
  before update on public.fixes
  for each row execute function public.handle_updated_at();

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
-- 6. Reports
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
create index if not exists idx_reports_user_risk_created
  on public.reports (user_id, risk_level, created_at desc);

drop trigger if exists trg_reports_updated_at on public.reports;
create trigger trg_reports_updated_at
  before update on public.reports
  for each row execute function public.handle_updated_at();

-- -----------------------------------------------------------------------------
-- 7. Timeline (Security Lifecycle Event Timeline)
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
create index if not exists idx_timeline_user_severity_timestamp
  on public.timeline (user_id, severity, timestamp desc);
create index if not exists idx_timeline_user_action_timestamp
  on public.timeline (user_id, action, timestamp desc);

-- -----------------------------------------------------------------------------
-- 8. Attack Simulations (Defensive & Educational)
-- -----------------------------------------------------------------------------
create table if not exists public.attack_simulations (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references public.scans (id) on delete cascade,
  vulnerability_id uuid not null references public.vulnerabilities (id) on delete cascade,
  project_id uuid references public.projects (id) on delete set null,
  user_id uuid not null references auth.users (id) on delete cascade,
  rule_id text not null,
  attack_type text not null default 'exploit_simulation',
  attack_name text not null,
  mitre_attack_technique text not null,
  severity text not null check (severity in ('critical', 'high', 'medium', 'low', 'info')),
  likelihood text not null check (likelihood in ('low', 'medium', 'high')),
  attack_payload text not null default '',
  before_result jsonb not null default '{}'::jsonb,
  after_result jsonb not null default '{}'::jsonb,
  success boolean not null default false,
  blocked boolean not null default true,
  animation_data jsonb not null default '{}'::jsonb,
  simulation_payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default timezone('utc', now())
);

create index if not exists idx_sim_scan
  on public.attack_simulations (scan_id);
create index if not exists idx_sim_vuln
  on public.attack_simulations (vulnerability_id);
create index if not exists idx_sim_project_created
  on public.attack_simulations (project_id, created_at desc)
  where project_id is not null;
create index if not exists idx_sim_user_created
  on public.attack_simulations (user_id, created_at desc);
create index if not exists idx_sim_user_blocked_created
  on public.attack_simulations (user_id, blocked, created_at desc);

-- -----------------------------------------------------------------------------
-- 9. Security Scores
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
create index if not exists idx_security_scores_user_project_calc
  on public.security_scores (user_id, project_id, calculated_at desc)
  where project_id is not null;

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
-- 10. Security Audit Logs
-- -----------------------------------------------------------------------------
create table if not exists public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users (id) on delete set null,
  action text not null,
  resource_type text not null,
  resource_id text,
  ip_address text,
  user_agent text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default timezone('utc', now())
);

create index if not exists idx_audit_logs_user_created
  on public.audit_logs (user_id, created_at desc);
create index if not exists idx_audit_logs_user_resource_created
  on public.audit_logs (user_id, resource_type, created_at desc);
create index if not exists idx_audit_logs_user_action_created
  on public.audit_logs (user_id, action, created_at desc);

-- =============================================================================
-- Backwards-Compatible Tables (Preserved for existing repositories & services)
-- =============================================================================

-- 11. User Profiles (linked 1:1 with Supabase Auth / Google OAuth users)
create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text not null,
  full_name text,
  avatar_url text,
  role text not null default 'user' check (role in ('user', 'admin')),
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now())
);

drop trigger if exists trg_profiles_updated_at on public.profiles;
create trigger trg_profiles_updated_at
  before update on public.profiles
  for each row execute function public.handle_updated_at();

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, full_name, avatar_url)
  values (
    new.id,
    coalesce(new.email, ''),
    coalesce(new.raw_user_meta_data ->> 'full_name', new.raw_user_meta_data ->> 'name'),
    new.raw_user_meta_data ->> 'avatar_url'
  )
  on conflict (id) do update
  set
    email = excluded.email,
    full_name = coalesce(excluded.full_name, public.profiles.full_name),
    avatar_url = coalesce(excluded.avatar_url, public.profiles.avatar_url),
    updated_at = timezone('utc', now());

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- 12. User-Defined Custom Security Rules
create table if not exists public.custom_rules (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  rule_key text not null,
  name text not null,
  description text not null,
  explanation text not null,
  severity text not null check (severity in ('critical', 'high', 'medium', 'low', 'info')),
  category text not null,
  cwe_id text not null,
  owasp_category text not null,
  languages text[] not null default array['typescript', 'javascript']::text[],
  pattern text not null,
  pattern_flags text not null default 'gi',
  remediation jsonb not null,
  enabled boolean not null default true,
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now()),
  unique (user_id, rule_key)
);

create index if not exists idx_custom_rules_user
  on public.custom_rules (user_id, enabled);

drop trigger if exists trg_custom_rules_updated_at on public.custom_rules;
create trigger trg_custom_rules_updated_at
  before update on public.custom_rules
  for each row execute function public.handle_updated_at();

-- 13. Legacy Security Reports (preserved for ReportRepository compatibility)
create table if not exists public.security_reports (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references public.scans (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  title text not null,
  format text not null default 'json' check (format in ('json', 'markdown')),
  report_payload jsonb not null,
  markdown_content text,
  created_at timestamptz not null default timezone('utc', now())
);

create index if not exists idx_reports_user_created
  on public.security_reports (user_id, created_at desc);
create index if not exists idx_reports_scan
  on public.security_reports (scan_id);

-- 14. Legacy Security Timeline (preserved for TimelineRepository compatibility)
create table if not exists public.security_timeline (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  project_id uuid references public.projects (id) on delete set null,
  project_name text not null,
  scan_id uuid null,
  timestamp timestamptz not null default timezone('utc', now()),
  action text not null,
  label text not null,
  description text null,
  severity text not null default 'info',
  status text not null default 'completed',
  metadata jsonb not null default '{}'::jsonb,

  constraint chk_security_timeline_project_name_non_empty
    check (char_length(trim(project_name)) > 0),
  constraint chk_security_timeline_label_non_empty
    check (char_length(trim(label)) > 0),
  constraint chk_security_timeline_action
    check (
      action in (
        'PROJECT_CREATED',
        'ANALYSIS_STARTED',
        'API_KEY_FOUND',
        'SQL_INJECTION_FOUND',
        'FIX_APPLIED',
        'ATTACK_SIMULATED',
        'REPORT_GENERATED',
        'DEPLOYMENT_APPROVED'
      )
    ),
  constraint chk_security_timeline_severity
    check (severity in ('critical', 'high', 'medium', 'low', 'info')),
  constraint chk_security_timeline_status
    check (status in ('pending', 'in_progress', 'completed', 'warning', 'blocked', 'approved')),
  constraint chk_security_timeline_metadata_is_object
    check (jsonb_typeof(metadata) = 'object')
);

create index if not exists idx_security_timeline_user_timestamp_desc
  on public.security_timeline (user_id, timestamp desc);
create index if not exists idx_security_timeline_user_project_timestamp_asc
  on public.security_timeline (user_id, project_name, timestamp asc);
create index if not exists idx_security_timeline_user_scan_timestamp_asc
  on public.security_timeline (user_id, scan_id, timestamp asc)
  where scan_id is not null;

-- =============================================================================
-- Row-Level Security (RLS) Policies
-- Strict user isolation: every user can only access and mutate their own data.
-- =============================================================================
alter table public.users enable row level security;
alter table public.projects enable row level security;
alter table public.scans enable row level security;
alter table public.vulnerabilities enable row level security;
alter table public.fixes enable row level security;
alter table public.reports enable row level security;
alter table public.timeline enable row level security;
alter table public.attack_simulations enable row level security;
alter table public.security_scores enable row level security;
alter table public.audit_logs enable row level security;
alter table public.profiles enable row level security;
alter table public.custom_rules enable row level security;
alter table public.security_reports enable row level security;
alter table public.security_timeline enable row level security;

-- users
drop policy if exists "users_select_own" on public.users;
create policy "users_select_own"
  on public.users for select using (auth.uid() = id);
drop policy if exists "users_insert_own" on public.users;
create policy "users_insert_own"
  on public.users for insert with check (auth.uid() = id);
drop policy if exists "users_update_own" on public.users;
create policy "users_update_own"
  on public.users for update using (auth.uid() = id) with check (auth.uid() = id);

-- projects
drop policy if exists "projects_select_own" on public.projects;
create policy "projects_select_own"
  on public.projects for select using (auth.uid() = user_id);
drop policy if exists "projects_insert_own" on public.projects;
create policy "projects_insert_own"
  on public.projects for insert with check (auth.uid() = user_id);
drop policy if exists "projects_update_own" on public.projects;
create policy "projects_update_own"
  on public.projects for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
drop policy if exists "projects_delete_own" on public.projects;
create policy "projects_delete_own"
  on public.projects for delete using (auth.uid() = user_id);

-- scans
drop policy if exists "scans_select_own" on public.scans;
create policy "scans_select_own"
  on public.scans for select using (auth.uid() = user_id);
drop policy if exists "scans_insert_own" on public.scans;
create policy "scans_insert_own"
  on public.scans for insert with check (auth.uid() = user_id);
drop policy if exists "scans_update_own" on public.scans;
create policy "scans_update_own"
  on public.scans for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
drop policy if exists "scans_delete_own" on public.scans;
create policy "scans_delete_own"
  on public.scans for delete using (auth.uid() = user_id);

-- vulnerabilities
drop policy if exists "vulnerabilities_select_own" on public.vulnerabilities;
create policy "vulnerabilities_select_own"
  on public.vulnerabilities for select using (auth.uid() = user_id);
drop policy if exists "vulnerabilities_insert_own" on public.vulnerabilities;
create policy "vulnerabilities_insert_own"
  on public.vulnerabilities for insert with check (auth.uid() = user_id);
drop policy if exists "vulnerabilities_update_own" on public.vulnerabilities;
create policy "vulnerabilities_update_own"
  on public.vulnerabilities for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
drop policy if exists "vulnerabilities_delete_own" on public.vulnerabilities;
create policy "vulnerabilities_delete_own"
  on public.vulnerabilities for delete using (auth.uid() = user_id);

-- fixes
drop policy if exists "fixes_select_own" on public.fixes;
create policy "fixes_select_own"
  on public.fixes for select using (auth.uid() = user_id);
drop policy if exists "fixes_insert_own" on public.fixes;
create policy "fixes_insert_own"
  on public.fixes for insert with check (auth.uid() = user_id);
drop policy if exists "fixes_update_own" on public.fixes;
create policy "fixes_update_own"
  on public.fixes for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
drop policy if exists "fixes_delete_own" on public.fixes;
create policy "fixes_delete_own"
  on public.fixes for delete using (auth.uid() = user_id);

-- reports
drop policy if exists "reports_select_own" on public.reports;
create policy "reports_select_own"
  on public.reports for select using (auth.uid() = user_id);
drop policy if exists "reports_insert_own" on public.reports;
create policy "reports_insert_own"
  on public.reports for insert with check (auth.uid() = user_id);
drop policy if exists "reports_update_own" on public.reports;
create policy "reports_update_own"
  on public.reports for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
drop policy if exists "reports_delete_own" on public.reports;
create policy "reports_delete_own"
  on public.reports for delete using (auth.uid() = user_id);

-- timeline
drop policy if exists "timeline_select_own" on public.timeline;
create policy "timeline_select_own"
  on public.timeline for select using (auth.uid() = user_id);
drop policy if exists "timeline_insert_own" on public.timeline;
create policy "timeline_insert_own"
  on public.timeline for insert with check (auth.uid() = user_id);
drop policy if exists "timeline_update_own" on public.timeline;
create policy "timeline_update_own"
  on public.timeline for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
drop policy if exists "timeline_delete_own" on public.timeline;
create policy "timeline_delete_own"
  on public.timeline for delete using (auth.uid() = user_id);

-- attack_simulations
drop policy if exists "attack_simulations_select_own" on public.attack_simulations;
create policy "attack_simulations_select_own"
  on public.attack_simulations for select using (auth.uid() = user_id);
drop policy if exists "attack_simulations_insert_own" on public.attack_simulations;
create policy "attack_simulations_insert_own"
  on public.attack_simulations for insert with check (auth.uid() = user_id);
drop policy if exists "attack_simulations_update_own" on public.attack_simulations;
create policy "attack_simulations_update_own"
  on public.attack_simulations for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
drop policy if exists "attack_simulations_delete_own" on public.attack_simulations;
create policy "attack_simulations_delete_own"
  on public.attack_simulations for delete using (auth.uid() = user_id);

-- security_scores
drop policy if exists "security_scores_select_own" on public.security_scores;
create policy "security_scores_select_own"
  on public.security_scores for select using (auth.uid() = user_id);
drop policy if exists "security_scores_insert_own" on public.security_scores;
create policy "security_scores_insert_own"
  on public.security_scores for insert with check (auth.uid() = user_id);
drop policy if exists "security_scores_update_own" on public.security_scores;
create policy "security_scores_update_own"
  on public.security_scores for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
drop policy if exists "security_scores_delete_own" on public.security_scores;
create policy "security_scores_delete_own"
  on public.security_scores for delete using (auth.uid() = user_id);

-- audit_logs (append-only for users)
drop policy if exists "audit_logs_select_own" on public.audit_logs;
create policy "audit_logs_select_own"
  on public.audit_logs for select using (auth.uid() = user_id);
drop policy if exists "audit_logs_insert_own" on public.audit_logs;
create policy "audit_logs_insert_own"
  on public.audit_logs for insert with check (auth.uid() = user_id);

-- profiles (backwards compat)
drop policy if exists "Users can view own profile" on public.profiles;
create policy "Users can view own profile"
  on public.profiles for select using (auth.uid() = id);
drop policy if exists "Users can update own profile" on public.profiles;
create policy "Users can update own profile"
  on public.profiles for update using (auth.uid() = id) with check (auth.uid() = id);

-- custom_rules (backwards compat)
drop policy if exists "Users can view own custom rules" on public.custom_rules;
create policy "Users can view own custom rules"
  on public.custom_rules for select using (auth.uid() = user_id);
drop policy if exists "Users can insert own custom rules" on public.custom_rules;
create policy "Users can insert own custom rules"
  on public.custom_rules for insert with check (auth.uid() = user_id);
drop policy if exists "Users can update own custom rules" on public.custom_rules;
create policy "Users can update own custom rules"
  on public.custom_rules for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
drop policy if exists "Users can delete own custom rules" on public.custom_rules;
create policy "Users can delete own custom rules"
  on public.custom_rules for delete using (auth.uid() = user_id);

-- security_reports (backwards compat)
drop policy if exists "Users can view own reports" on public.security_reports;
create policy "Users can view own reports"
  on public.security_reports for select using (auth.uid() = user_id);
drop policy if exists "Users can insert own reports" on public.security_reports;
create policy "Users can insert own reports"
  on public.security_reports for insert with check (auth.uid() = user_id);
drop policy if exists "Users can delete own reports" on public.security_reports;
create policy "Users can delete own reports"
  on public.security_reports for delete using (auth.uid() = user_id);

-- security_timeline (backwards compat)
drop policy if exists "security_timeline_select_own" on public.security_timeline;
create policy "security_timeline_select_own"
  on public.security_timeline for select using (auth.uid() = user_id);
drop policy if exists "security_timeline_insert_own" on public.security_timeline;
create policy "security_timeline_insert_own"
  on public.security_timeline for insert with check (auth.uid() = user_id);
drop policy if exists "security_timeline_update_own" on public.security_timeline;
create policy "security_timeline_update_own"
  on public.security_timeline for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
drop policy if exists "security_timeline_delete_own" on public.security_timeline;
create policy "security_timeline_delete_own"
  on public.security_timeline for delete using (auth.uid() = user_id);

-- =============================================================================
-- Safe SQL RPC Helper Functions (RLS-Respecting / SECURITY INVOKER)
-- =============================================================================

create or replace function public.get_monthly_activity(p_months integer default 6)
returns table (
  month_start date,
  month_label text,
  scans_count bigint,
  vulnerabilities_found bigint,
  fixes_applied bigint,
  simulations_run bigint,
  avg_security_score numeric(5, 2),
  threats_fixed bigint,
  time_saved_minutes bigint
)
language sql
stable
security invoker
set search_path = public
as $$
  with params as (
    select
      auth.uid() as uid,
      greatest(1, least(coalesce(p_months, 6), 24)) as months_window
  ),
  months as (
    select
      date_trunc('month', timezone('utc', now()))::date - (gs.idx || ' months')::interval as m_start
    from params p
    cross join lateral generate_series(0, p.months_window - 1) as gs(idx)
    where p.uid is not null
  ),
  scan_agg as (
    select
      date_trunc('month', s.created_at at time zone 'utc')::date as m_start,
      count(*)::bigint as cnt
    from public.scans s
    cross join params p
    where s.user_id = p.uid
      and s.created_at >= date_trunc('month', timezone('utc', now())) - ((p.months_window - 1) || ' months')::interval
    group by 1
  ),
  vuln_agg as (
    select
      date_trunc('month', v.created_at at time zone 'utc')::date as m_start,
      count(*)::bigint as cnt
    from public.vulnerabilities v
    cross join params p
    where v.user_id = p.uid
      and v.created_at >= date_trunc('month', timezone('utc', now())) - ((p.months_window - 1) || ' months')::interval
    group by 1
  ),
  fix_agg as (
    select
      date_trunc('month', coalesce(f.applied_at, f.created_at) at time zone 'utc')::date as m_start,
      count(*)::bigint as cnt
    from public.fixes f
    cross join params p
    where f.user_id = p.uid
      and f.applied = true
      and coalesce(f.applied_at, f.created_at) >= date_trunc('month', timezone('utc', now())) - ((p.months_window - 1) || ' months')::interval
    group by 1
  ),
  sim_agg as (
    select
      date_trunc('month', a.created_at at time zone 'utc')::date as m_start,
      count(*)::bigint as cnt
    from public.attack_simulations a
    cross join params p
    where a.user_id = p.uid
      and a.created_at >= date_trunc('month', timezone('utc', now())) - ((p.months_window - 1) || ' months')::interval
    group by 1
  ),
  score_agg as (
    select
      date_trunc('month', sc.calculated_at at time zone 'utc')::date as m_start,
      round(avg(sc.score)::numeric, 2) as avg_score,
      coalesce(sum(sc.threats_fixed), 0)::bigint as threats_fixed_sum,
      coalesce(sum(sc.time_saved_minutes), 0)::bigint as time_saved_sum
    from public.security_scores sc
    cross join params p
    where sc.user_id = p.uid
      and sc.calculated_at >= date_trunc('month', timezone('utc', now())) - ((p.months_window - 1) || ' months')::interval
    group by 1
  )
  select
    m.m_start::date as month_start,
    to_char(m.m_start, 'Mon YYYY') as month_label,
    coalesce(sa.cnt, 0) as scans_count,
    coalesce(va.cnt, 0) as vulnerabilities_found,
    coalesce(fa.cnt, 0) as fixes_applied,
    coalesce(sma.cnt, 0) as simulations_run,
    coalesce(sca.avg_score, 0.00)::numeric(5, 2) as avg_security_score,
    coalesce(sca.threats_fixed_sum, 0) as threats_fixed,
    coalesce(sca.time_saved_sum, 0) as time_saved_minutes
  from months m
  left join scan_agg sa on sa.m_start = m.m_start::date
  left join vuln_agg va on va.m_start = m.m_start::date
  left join fix_agg fa on fa.m_start = m.m_start::date
  left join sim_agg sma on sma.m_start = m.m_start::date
  left join score_agg sca on sca.m_start = m.m_start::date
  order by m.m_start asc;
$$;

revoke all on function public.get_monthly_activity(integer) from public;
grant execute on function public.get_monthly_activity(integer) to authenticated;

create or replace function public.get_project_leaderboard(p_limit integer default 10)
returns table (
  rank_position bigint,
  project_id uuid,
  project_name text,
  slug text,
  primary_language text,
  latest_security_score integer,
  risk_level text,
  total_scans bigint,
  open_vulnerabilities bigint,
  fixes_applied bigint,
  last_scan_at timestamptz
)
language sql
stable
security invoker
set search_path = public
as $$
  with params as (
    select
      auth.uid() as uid,
      greatest(1, least(coalesce(p_limit, 10), 100)) as row_limit
  ),
  scan_stats as (
    select
      s.project_id,
      count(*)::bigint as total_scans,
      max(s.created_at) as last_scan_at
    from public.scans s
    cross join params p
    where s.user_id = p.uid
      and s.project_id is not null
    group by s.project_id
  ),
  vuln_stats as (
    select
      v.project_id,
      count(*)::bigint as open_vulnerabilities
    from public.vulnerabilities v
    cross join params p
    where v.user_id = p.uid
      and v.project_id is not null
      and v.status = 'open'
    group by v.project_id
  ),
  fix_stats as (
    select
      f.project_id,
      count(*)::bigint as fixes_applied
    from public.fixes f
    cross join params p
    where f.user_id = p.uid
      and f.project_id is not null
      and f.applied = true
    group by f.project_id
  )
  select
    row_number() over (
      order by pr.latest_security_score desc, coalesce(vs.open_vulnerabilities, 0) asc, pr.updated_at desc
    ) as rank_position,
    pr.id as project_id,
    pr.name as project_name,
    pr.slug,
    pr.primary_language,
    pr.latest_security_score,
    pr.risk_level,
    coalesce(ss.total_scans, 0) as total_scans,
    coalesce(vs.open_vulnerabilities, 0) as open_vulnerabilities,
    coalesce(fs.fixes_applied, 0) as fixes_applied,
    ss.last_scan_at
  from public.projects pr
  cross join params p
  left join scan_stats ss on ss.project_id = pr.id
  left join vuln_stats vs on vs.project_id = pr.id
  left join fix_stats fs on fs.project_id = pr.id
  where p.uid is not null
    and pr.user_id = p.uid
    and pr.status = 'active'
  order by pr.latest_security_score desc, coalesce(vs.open_vulnerabilities, 0) asc, pr.updated_at desc
  limit (select row_limit from params);
$$;

revoke all on function public.get_project_leaderboard(integer) from public;
grant execute on function public.get_project_leaderboard(integer) to authenticated;
