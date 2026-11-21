-- =============================================================================
-- Migration 004: Comprehensive RLS Verification, Performance Indexes & RPCs
-- Sentinel AI - Security Hardening & Dashboard Query Optimization
--
-- Covers:
--   1. Idempotent RLS enforcement & strict `auth.uid()` policies on all 10 core
--      tables + backwards-compatible tables (profiles, custom_rules,
--      security_reports, security_timeline).
--   2. Composite & partial indexes for dashboard summaries, monthly activity
--      aggregations, vulnerability triage, and project leaderboard queries.
--   3. Safe, RLS-respecting SQL RPC helper functions:
--        - public.get_monthly_activity(p_months integer default 6)
--        - public.get_project_leaderboard(p_limit integer default 10)
-- =============================================================================

-- =============================================================================
-- 1. Comprehensive Row-Level Security (RLS) Verification
-- =============================================================================

-- Enable RLS across all 10 core tables
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

-- Enable RLS across backwards-compatible tables if present
do $$
begin
  if to_regclass('public.profiles') is not null then
    execute 'alter table public.profiles enable row level security';
  end if;
  if to_regclass('public.custom_rules') is not null then
    execute 'alter table public.custom_rules enable row level security';
  end if;
  if to_regclass('public.security_reports') is not null then
    execute 'alter table public.security_reports enable row level security';
  end if;
  if to_regclass('public.security_timeline') is not null then
    execute 'alter table public.security_timeline enable row level security';
  end if;
end $$;

-- Ensure strict WITH CHECK on updates for existing core tables from initial schema
-- scans
drop policy if exists "Users can view own scans" on public.scans;
drop policy if exists "scans_select_own" on public.scans;
create policy "scans_select_own"
  on public.scans for select
  using (auth.uid() = user_id);

drop policy if exists "Users can create own scans" on public.scans;
drop policy if exists "scans_insert_own" on public.scans;
create policy "scans_insert_own"
  on public.scans for insert
  with check (auth.uid() = user_id);

drop policy if exists "Users can update own scans" on public.scans;
drop policy if exists "scans_update_own" on public.scans;
create policy "scans_update_own"
  on public.scans for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists "Users can delete own scans" on public.scans;
drop policy if exists "scans_delete_own" on public.scans;
create policy "scans_delete_own"
  on public.scans for delete
  using (auth.uid() = user_id);

-- vulnerabilities
drop policy if exists "Users can view own vulnerabilities" on public.vulnerabilities;
drop policy if exists "vulnerabilities_select_own" on public.vulnerabilities;
create policy "vulnerabilities_select_own"
  on public.vulnerabilities for select
  using (auth.uid() = user_id);

drop policy if exists "Users can insert own vulnerabilities" on public.vulnerabilities;
drop policy if exists "vulnerabilities_insert_own" on public.vulnerabilities;
create policy "vulnerabilities_insert_own"
  on public.vulnerabilities for insert
  with check (auth.uid() = user_id);

drop policy if exists "Users can update own vulnerabilities" on public.vulnerabilities;
drop policy if exists "vulnerabilities_update_own" on public.vulnerabilities;
create policy "vulnerabilities_update_own"
  on public.vulnerabilities for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists "Users can delete own vulnerabilities" on public.vulnerabilities;
drop policy if exists "vulnerabilities_delete_own" on public.vulnerabilities;
create policy "vulnerabilities_delete_own"
  on public.vulnerabilities for delete
  using (auth.uid() = user_id);

-- attack_simulations
drop policy if exists "Users can view own simulations" on public.attack_simulations;
drop policy if exists "attack_simulations_select_own" on public.attack_simulations;
create policy "attack_simulations_select_own"
  on public.attack_simulations for select
  using (auth.uid() = user_id);

drop policy if exists "Users can insert own simulations" on public.attack_simulations;
drop policy if exists "attack_simulations_insert_own" on public.attack_simulations;
create policy "attack_simulations_insert_own"
  on public.attack_simulations for insert
  with check (auth.uid() = user_id);

drop policy if exists "attack_simulations_update_own" on public.attack_simulations;
create policy "attack_simulations_update_own"
  on public.attack_simulations for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists "Users can delete own simulations" on public.attack_simulations;
drop policy if exists "attack_simulations_delete_own" on public.attack_simulations;
create policy "attack_simulations_delete_own"
  on public.attack_simulations for delete
  using (auth.uid() = user_id);

-- audit_logs (append-only for authenticated users: SELECT and INSERT only)
drop policy if exists "Users can view own audit logs" on public.audit_logs;
drop policy if exists "audit_logs_select_own" on public.audit_logs;
create policy "audit_logs_select_own"
  on public.audit_logs for select
  using (auth.uid() = user_id);

drop policy if exists "Users can insert own audit logs" on public.audit_logs;
drop policy if exists "audit_logs_insert_own" on public.audit_logs;
create policy "audit_logs_insert_own"
  on public.audit_logs for insert
  with check (auth.uid() = user_id);

-- =============================================================================
-- 2. Composite & Partial Performance Indexes
-- =============================================================================

-- Dashboard & leaderboard: active projects ranked by security score
create index if not exists idx_projects_active_leaderboard
  on public.projects (user_id, latest_security_score desc, updated_at desc)
  where status = 'active';

create index if not exists idx_projects_user_risk_level
  on public.projects (user_id, risk_level, updated_at desc);

-- Scans: dashboard recent completed scans & project-scoped history
create index if not exists idx_scans_user_status_created
  on public.scans (user_id, status, created_at desc);

create index if not exists idx_scans_user_project_created
  on public.scans (user_id, project_id, created_at desc)
  where project_id is not null;

-- Vulnerabilities: open vulnerability triage & high-priority partial index
create index if not exists idx_vuln_user_status_severity_created
  on public.vulnerabilities (user_id, status, severity, created_at desc);

create index if not exists idx_vuln_open_critical_high
  on public.vulnerabilities (user_id, project_id, created_at desc)
  where status = 'open' and severity in ('critical', 'high');

create index if not exists idx_vuln_user_created
  on public.vulnerabilities (user_id, created_at desc);

-- Fixes: applied fixes metrics & pending fixes lookup
create index if not exists idx_fixes_user_applied_at
  on public.fixes (user_id, applied_at desc)
  where applied = true;

create index if not exists idx_fixes_user_project_applied
  on public.fixes (user_id, project_id, applied)
  where project_id is not null;

-- Reports: fast lookup by user, risk level, and format
create index if not exists idx_reports_user_risk_created
  on public.reports (user_id, risk_level, created_at desc);

-- Timeline: filtered activity feed by action & severity
create index if not exists idx_timeline_user_severity_timestamp
  on public.timeline (user_id, severity, timestamp desc);

create index if not exists idx_timeline_user_action_timestamp
  on public.timeline (user_id, action, timestamp desc);

-- Attack simulations: blocked vs unblocked analytics
create index if not exists idx_sim_user_blocked_created
  on public.attack_simulations (user_id, blocked, created_at desc);

-- Security scores: monthly trend & project-latest lookups
create index if not exists idx_security_scores_user_project_calc
  on public.security_scores (user_id, project_id, calculated_at desc)
  where project_id is not null;

-- Audit logs: resource & action filtering
create index if not exists idx_audit_logs_user_resource_created
  on public.audit_logs (user_id, resource_type, created_at desc);

create index if not exists idx_audit_logs_user_action_created
  on public.audit_logs (user_id, action, created_at desc);

-- =============================================================================
-- 3. Safe SQL RPC Helper Functions (RLS-Respecting / SECURITY INVOKER)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- RPC 1: public.get_monthly_activity(p_months integer default 6)
-- Returns monthly aggregated security activity for the authenticated user.
-- Clamps p_months to [1, 24] to prevent unbounded series generation.
-- -----------------------------------------------------------------------------
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

-- -----------------------------------------------------------------------------
-- RPC 2: public.get_project_leaderboard(p_limit integer default 10)
-- Returns the authenticated user's active projects ranked by security score.
-- Clamps p_limit to [1, 100].
-- -----------------------------------------------------------------------------
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
