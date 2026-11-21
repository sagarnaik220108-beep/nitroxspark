-- =============================================================================
-- Migration 002: Security Timeline Table, Constraints, Indexes & Strict RLS
-- Sentinel AI - Security Lifecycle Event Timeline
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Security Timeline Table
-- -----------------------------------------------------------------------------
create table if not exists public.security_timeline (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
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
    check (
      status in (
        'pending',
        'in_progress',
        'completed',
        'warning',
        'blocked',
        'approved'
      )
    ),

  constraint chk_security_timeline_metadata_is_object
    check (jsonb_typeof(metadata) = 'object')
);

-- -----------------------------------------------------------------------------
-- 2. Indexes for Ordered Timeline Queries
-- -----------------------------------------------------------------------------
create index if not exists idx_security_timeline_user_timestamp_desc
  on public.security_timeline (user_id, timestamp desc);

create index if not exists idx_security_timeline_user_project_timestamp_asc
  on public.security_timeline (user_id, project_name, timestamp asc);

create index if not exists idx_security_timeline_user_scan_timestamp_asc
  on public.security_timeline (user_id, scan_id, timestamp asc)
  where scan_id is not null;

-- -----------------------------------------------------------------------------
-- 3. Strict Row-Level Security (RLS)
--    Users can only view, insert, update, and delete their own timeline events.
-- -----------------------------------------------------------------------------
alter table public.security_timeline enable row level security;

drop policy if exists "security_timeline_select_own" on public.security_timeline;
create policy "security_timeline_select_own"
  on public.security_timeline
  for select
  using (auth.uid() = user_id);

drop policy if exists "security_timeline_insert_own" on public.security_timeline;
create policy "security_timeline_insert_own"
  on public.security_timeline
  for insert
  with check (auth.uid() = user_id);

drop policy if exists "security_timeline_update_own" on public.security_timeline;
create policy "security_timeline_update_own"
  on public.security_timeline
  for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists "security_timeline_delete_own" on public.security_timeline;
create policy "security_timeline_delete_own"
  on public.security_timeline
  for delete
  using (auth.uid() = user_id);
