import type { PostgrestError, SupabaseClient } from "@supabase/supabase-js";
import { z } from "zod";
import { calculateSecurityScore } from "@/security";
import {
  authService,
  type AuthenticatedContext,
  type SupabaseServerClient,
} from "@/services/auth.service";
import type {
  PaginationMeta,
  ScanStatus,
  SecurityScoreReport,
  Severity,
  SeverityBreakdown,
  SupportedLanguage,
  VulnerabilityCategory,
  VulnerabilityStatus,
} from "@/types";
import type {
  CategoryBreakdownDatum,
  DashboardChartsData,
  DashboardChartsResponse,
  DashboardLeaderboardQueryParams,
  DashboardOverviewQueryParams,
  DashboardOverviewResponse,
  DashboardPaginationParams,
  DashboardProjectSummary,
  DashboardScanSummary,
  DashboardThreatStats,
  DashboardVulnerabilitiesQueryParams,
  DashboardVulnerabilitySummary,
  LeaderboardEntry,
  LeaderboardScope,
  MonthlyActivityPoint,
  PaginatedCollection,
  ScanRiskTrendPoint,
  SeverityDistributionDatum,
  TopCategoryStat,
  TopRuleStat,
} from "@/types/dashboard.types";
import type {
  TimelineAction,
  TimelineEvent,
  TimelineSeverity,
  TimelineStatus,
} from "@/types/timeline.types";
import {
  InternalServerError,
  severitySchema,
  uuidParamSchema,
  vulnerabilityStatusSchema,
} from "@/utils";

const DEFAULT_PAGE = 1;
const DEFAULT_PAGE_SIZE = 10;
const MAX_PAGE_SIZE = 100;
const DEFAULT_MONTHS = 12;
const MAX_MONTHS = 24;
const MAX_RISK_TREND_POINTS = 20;
const TOP_CATEGORIES_LIMIT = 6;
const TOP_RULES_LIMIT = 8;

const SEVERITY_ORDER: readonly Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

const SEVERITY_LABELS: Readonly<Record<Severity, string>> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const CATEGORY_LABELS: Readonly<Record<VulnerabilityCategory, string>> = {
  injection: "Injection",
  xss: "Cross-Site Scripting (XSS)",
  secrets: "Hardcoded Secrets",
  authentication: "Authentication",
  authorization: "Authorization",
  ssrf: "SSRF",
  "path-traversal": "Path Traversal",
  cryptography: "Cryptography",
  misconfiguration: "Misconfiguration",
  deserialization: "Deserialization",
  other: "Other",
};

/**
 * Local typed row definitions for `public.projects` and `public.security_timeline`
 * so `DashboardService` remains strictly typed without modifying `types/database.types.ts`.
 */
interface ProjectRow {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  repository_url: string | null;
  language: SupportedLanguage | null;
  created_at: string;
  updated_at: string;
}

interface SecurityTimelineRow {
  id: string;
  user_id: string;
  project_name: string;
  scan_id: string | null;
  timestamp: string;
  action: TimelineAction;
  label: string;
  description: string | null;
  severity: TimelineSeverity;
  status: TimelineStatus;
  metadata: Record<string, unknown>;
}

interface DashboardExtendedSchema {
  public: {
    Tables: {
      projects: {
        Row: ProjectRow;
        Insert: {
          id?: string;
          user_id: string;
          name: string;
          description?: string | null;
          repository_url?: string | null;
          language?: SupportedLanguage | null;
          created_at?: string;
          updated_at?: string;
        };
        Update: {
          name?: string;
          description?: string | null;
          repository_url?: string | null;
          language?: SupportedLanguage | null;
          updated_at?: string;
        };
        Relationships: [];
      };
      security_timeline: {
        Row: SecurityTimelineRow;
        Insert: {
          id?: string;
          user_id: string;
          project_name: string;
          scan_id?: string | null;
          timestamp?: string;
          action: TimelineAction;
          label: string;
          description?: string | null;
          severity?: TimelineSeverity;
          status?: TimelineStatus;
          metadata?: Record<string, unknown>;
        };
        Update: {
          project_name?: string;
          scan_id?: string | null;
          timestamp?: string;
          action?: TimelineAction;
          label?: string;
          description?: string | null;
          severity?: TimelineSeverity;
          status?: TimelineStatus;
          metadata?: Record<string, unknown>;
        };
        Relationships: [];
      };
    };
    Views: Record<string, never>;
    Functions: Record<string, never>;
    Enums: Record<string, never>;
    CompositeTypes: Record<string, never>;
  };
}

/**
 * Minimal scan projection used for analytics, project aggregation, and trends.
 */
interface ScanMetricsRow {
  id: string;
  project_name: string;
  file_name: string;
  language: SupportedLanguage;
  risk_score: number;
  risk_grade: "A" | "B" | "C" | "D" | "F";
  severity_breakdown: SeverityBreakdown;
  created_at: string;
}

/**
 * Minimal scan projection returned in paginated scan listings.
 */
interface ScanListRow extends ScanMetricsRow {
  status: ScanStatus;
  executed_rules_count: number;
  duration_ms: number;
}

/**
 * Minimal vulnerability projection used for scoring, charts, and threat stats.
 */
interface VulnerabilityMetricsRow {
  scan_id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  category: VulnerabilityCategory;
  status: VulnerabilityStatus;
  created_at: string;
  updated_at: string;
}

/**
 * Minimal vulnerability projection returned in paginated vulnerability listings.
 */
interface VulnerabilityListRow extends VulnerabilityMetricsRow {
  id: string;
  cwe_id: string;
  owasp_category: string;
  confidence: number;
  line_start: number;
  line_end: number;
}

interface ProfileProjectionRow {
  id: string;
  email: string;
  full_name: string | null;
  avatar_url: string | null;
}

const leaderboardScopeSchema: z.ZodType<LeaderboardScope> = z.enum([
  "all",
  "projects",
  "developers",
]);

export const dashboardPaginationSchema = z.object({
  page: z.coerce.number().int().min(1).default(DEFAULT_PAGE),
  pageSize: z.coerce
    .number()
    .int()
    .min(1)
    .max(MAX_PAGE_SIZE)
    .default(DEFAULT_PAGE_SIZE),
});

export const dashboardVulnerabilitiesQuerySchema =
  dashboardPaginationSchema.extend({
    severity: severitySchema.optional(),
    status: vulnerabilityStatusSchema.optional(),
    scanId: uuidParamSchema.optional(),
  });

export const dashboardChartsQuerySchema = z.object({
  months: z.coerce
    .number()
    .int()
    .min(1)
    .max(MAX_MONTHS)
    .default(DEFAULT_MONTHS),
});

export const dashboardLeaderboardQuerySchema =
  dashboardPaginationSchema.extend({
    scope: leaderboardScopeSchema.default("all"),
  });

export const dashboardOverviewQuerySchema = dashboardPaginationSchema.extend({
  months: z.coerce
    .number()
    .int()
    .min(1)
    .max(MAX_MONTHS)
    .default(DEFAULT_MONTHS),
  severity: severitySchema.optional(),
  status: vulnerabilityStatusSchema.optional(),
  leaderboardScope: leaderboardScopeSchema.default("all"),
});

function getExtendedClient(
  supabase: SupabaseServerClient
): SupabaseClient<DashboardExtendedSchema> {
  return supabase as unknown as SupabaseClient<DashboardExtendedSchema>;
}

function isMissingTableError(error: PostgrestError | null): boolean {
  if (!error) return false;
  if (error.code === "42P01" || error.code === "PGRST205") {
    return true;
  }
  const message = error.message.toLowerCase();
  return (
    message.includes("does not exist") ||
    message.includes("could not find the table")
  );
}

function createEmptySeverityBreakdown(): SeverityBreakdown {
  return {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
}

function normalizeSeverityBreakdown(value: unknown): SeverityBreakdown {
  const base = createEmptySeverityBreakdown();
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const record = value as Partial<Record<Severity, unknown>>;
    for (const severity of SEVERITY_ORDER) {
      const candidate = record[severity];
      if (typeof candidate === "number" && Number.isFinite(candidate)) {
        base[severity] = Math.max(0, Math.floor(candidate));
      }
    }
  }
  return base;
}

function normalizeMetadata(value: unknown): Record<string, unknown> {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
}

function roundToOneDecimal(value: number): number {
  return Math.round(value * 10) / 10;
}

function computePercentage(part: number, total: number): number {
  if (total <= 0) return 0;
  return roundToOneDecimal((part / total) * 100);
}

function buildPaginationMeta(
  page: number,
  pageSize: number,
  total: number
): PaginationMeta {
  return {
    page,
    pageSize,
    total,
    totalPages: total === 0 ? 0 : Math.ceil(total / pageSize),
  };
}

function paginateArray<T>(
  items: readonly T[],
  page: number,
  pageSize: number
): PaginatedCollection<T> {
  const total = items.length;
  const start = (page - 1) * pageSize;
  const sliced = items.slice(start, start + pageSize);
  return {
    items: sliced,
    pagination: buildPaginationMeta(page, pageSize, total),
  };
}

function formatUtcYearMonth(date: Date): string {
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  return `${year}-${month}`;
}

function extractYearMonthFromIso(isoTimestamp: string): string | null {
  const parsed = new Date(isoTimestamp);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }
  return formatUtcYearMonth(parsed);
}

function getRecentYearMonthKeys(months: number): string[] {
  const clampedMonths = Math.max(1, Math.min(MAX_MONTHS, Math.floor(months)));
  const now = new Date();
  const keys: string[] = [];

  for (let offset = clampedMonths - 1; offset >= 0; offset -= 1) {
    const d = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - offset, 1)
    );
    keys.push(formatUtcYearMonth(d));
  }

  return keys;
}

function mapScanRowToSummary(row: ScanListRow): DashboardScanSummary {
  return {
    id: row.id,
    projectName: row.project_name,
    fileName: row.file_name,
    language: row.language,
    status: row.status,
    riskScore: row.risk_score,
    riskGrade: row.risk_grade,
    severityBreakdown: normalizeSeverityBreakdown(row.severity_breakdown),
    executedRulesCount: row.executed_rules_count,
    durationMs: row.duration_ms,
    createdAt: row.created_at,
  };
}

function mapVulnerabilityRowToSummary(
  row: VulnerabilityListRow
): DashboardVulnerabilitySummary {
  return {
    id: row.id,
    scanId: row.scan_id,
    ruleId: row.rule_id,
    title: row.title,
    severity: row.severity,
    category: row.category,
    cweId: row.cwe_id,
    owaspCategory: row.owasp_category,
    confidence: Number(row.confidence),
    lineStart: row.line_start,
    lineEnd: row.line_end,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapTimelineRowToEvent(row: SecurityTimelineRow): TimelineEvent {
  return {
    id: row.id,
    userId: row.user_id,
    projectName: row.project_name,
    scanId: row.scan_id,
    timestamp: row.timestamp,
    action: row.action,
    label: row.label,
    description: row.description,
    severity: row.severity,
    status: row.status,
    metadata: normalizeMetadata(row.metadata),
  };
}

function slugifyProjectId(projectName: string): string {
  const slug = projectName
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return `project-${slug || "untitled"}`;
}

/**
 * Computes a live `SecurityScoreReport` from minimal scan & vulnerability telemetry.
 */
function computeLiveSecurityScore(
  filesScanned: number,
  vulnerabilities: readonly VulnerabilityMetricsRow[]
): SecurityScoreReport {
  let criticalIssues = 0;
  let highIssues = 0;
  let mediumIssues = 0;
  let lowIssues = 0;
  let threatsFixed = 0;

  for (const vuln of vulnerabilities) {
    if (vuln.status === "fixed") {
      threatsFixed += 1;
      continue;
    }
    if (vuln.status === "false_positive") {
      continue;
    }

    switch (vuln.severity) {
      case "critical":
        criticalIssues += 1;
        break;
      case "high":
        highIssues += 1;
        break;
      case "medium":
        mediumIssues += 1;
        break;
      case "low":
        lowIssues += 1;
        break;
      case "info":
        break;
    }
  }

  return calculateSecurityScore({
    criticalIssues,
    highIssues,
    mediumIssues,
    lowIssues,
    filesScanned,
    threatsFixed,
  });
}

/**
 * Computes aggregate threat statistics from minimal vulnerability rows.
 */
function computeThreatStats(
  vulnerabilities: readonly VulnerabilityMetricsRow[]
): DashboardThreatStats {
  const severityBreakdown = createEmptySeverityBreakdown();
  const categoryCounts = new Map<VulnerabilityCategory, number>();
  const ruleCounts = new Map<
    string,
    { ruleId: string; title: string; severity: Severity; count: number }
  >();

  let open = 0;
  let acknowledged = 0;
  let fixed = 0;
  let falsePositive = 0;

  for (const vuln of vulnerabilities) {
    severityBreakdown[vuln.severity] += 1;

    switch (vuln.status) {
      case "open":
        open += 1;
        break;
      case "acknowledged":
        acknowledged += 1;
        break;
      case "fixed":
        fixed += 1;
        break;
      case "false_positive":
        falsePositive += 1;
        break;
    }

    categoryCounts.set(
      vuln.category,
      (categoryCounts.get(vuln.category) ?? 0) + 1
    );

    const existingRule = ruleCounts.get(vuln.rule_id);
    if (existingRule) {
      existingRule.count += 1;
    } else {
      ruleCounts.set(vuln.rule_id, {
        ruleId: vuln.rule_id,
        title: vuln.title,
        severity: vuln.severity,
        count: 1,
      });
    }
  }

  const totalDetected = vulnerabilities.length;
  const actionableTotal = totalDetected - falsePositive;
  const fixRatePercentage = computePercentage(fixed, actionableTotal);

  const topCategories: TopCategoryStat[] = Array.from(categoryCounts.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, TOP_CATEGORIES_LIMIT)
    .map(([category, count]) => ({
      category,
      label: CATEGORY_LABELS[category],
      count,
      percentage: computePercentage(count, totalDetected),
    }));

  const topRules: TopRuleStat[] = Array.from(ruleCounts.values())
    .sort((a, b) => b.count - a.count || a.ruleId.localeCompare(b.ruleId))
    .slice(0, TOP_RULES_LIMIT);

  return {
    totalDetected,
    open,
    acknowledged,
    fixed,
    falsePositive,
    severityBreakdown,
    fixRatePercentage,
    topCategories,
    topRules,
  };
}

/**
 * Builds chart-ready datasets for severity distribution, category breakdown, and scan risk trend.
 */
function buildChartsData(
  scans: readonly ScanMetricsRow[],
  vulnerabilities: readonly VulnerabilityMetricsRow[],
  threatStats: DashboardThreatStats
): DashboardChartsData {
  const totalDetected = threatStats.totalDetected;

  const severityDistribution: SeverityDistributionDatum[] = SEVERITY_ORDER.map(
    (severity) => {
      const count = threatStats.severityBreakdown[severity];
      return {
        severity,
        label: SEVERITY_LABELS[severity],
        count,
        percentage: computePercentage(count, totalDetected),
      };
    }
  );

  const categoryCounts = new Map<VulnerabilityCategory, number>();
  for (const vuln of vulnerabilities) {
    categoryCounts.set(
      vuln.category,
      (categoryCounts.get(vuln.category) ?? 0) + 1
    );
  }

  const categoryBreakdown: CategoryBreakdownDatum[] = Array.from(
    categoryCounts.entries()
  )
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([category, count]) => ({
      category,
      label: CATEGORY_LABELS[category],
      count,
      percentage: computePercentage(count, totalDetected),
    }));

  // `scans` are ordered newest-first; take most recent N and reverse for chronological plotting.
  const scanRiskTrend: ScanRiskTrendPoint[] = scans
    .slice(0, MAX_RISK_TREND_POINTS)
    .reverse()
    .map((scan) => {
      const breakdown = normalizeSeverityBreakdown(scan.severity_breakdown);
      const totalFindings =
        breakdown.critical +
        breakdown.high +
        breakdown.medium +
        breakdown.low +
        breakdown.info;
      return {
        scanId: scan.id,
        projectName: scan.project_name,
        fileName: scan.file_name,
        riskScore: scan.risk_score,
        securityScore: Math.max(0, Math.min(100, 100 - scan.risk_score)),
        riskGrade: scan.risk_grade,
        totalFindings,
        createdAt: scan.created_at,
      };
    });

  return {
    severityDistribution,
    categoryBreakdown,
    scanRiskTrend,
  };
}

/**
 * Aggregates scan and vulnerability activity over the last `months` UTC calendar months (`YYYY-MM`).
 */
function buildMonthlyActivity(
  scans: readonly ScanMetricsRow[],
  vulnerabilities: readonly VulnerabilityMetricsRow[],
  months: number
): MonthlyActivityPoint[] {
  const monthKeys = getRecentYearMonthKeys(months);
  const buckets = new Map<
    string,
    {
      scansCount: number;
      riskScoreSum: number;
      vulnerabilitiesFound: number;
      threatsFixed: number;
    }
  >();

  for (const key of monthKeys) {
    buckets.set(key, {
      scansCount: 0,
      riskScoreSum: 0,
      vulnerabilitiesFound: 0,
      threatsFixed: 0,
    });
  }

  for (const scan of scans) {
    const key = extractYearMonthFromIso(scan.created_at);
    if (!key) continue;
    const bucket = buckets.get(key);
    if (!bucket) continue;
    bucket.scansCount += 1;
    bucket.riskScoreSum += scan.risk_score;
  }

  for (const vuln of vulnerabilities) {
    const createdKey = extractYearMonthFromIso(vuln.created_at);
    if (createdKey) {
      const createdBucket = buckets.get(createdKey);
      if (createdBucket) {
        createdBucket.vulnerabilitiesFound += 1;
      }
    }

    if (vuln.status === "fixed") {
      const fixedKey = extractYearMonthFromIso(
        vuln.updated_at || vuln.created_at
      );
      if (fixedKey) {
        const fixedBucket = buckets.get(fixedKey);
        if (fixedBucket) {
          fixedBucket.threatsFixed += 1;
        }
      }
    }
  }

  return monthKeys.map((month) => {
    const bucket = buckets.get(month);
    const scansCount = bucket?.scansCount ?? 0;
    const avgRiskScore =
      scansCount > 0 && bucket
        ? roundToOneDecimal(bucket.riskScoreSum / scansCount)
        : 0;

    return {
      month,
      scansCount,
      vulnerabilitiesFound: bucket?.vulnerabilitiesFound ?? 0,
      threatsFixed: bucket?.threatsFixed ?? 0,
      avgRiskScore,
    };
  });
}

interface ProjectTelemetryAggregate {
  scans: ScanMetricsRow[];
  vulnerabilities: VulnerabilityMetricsRow[];
}

function groupTelemetryByProject(
  scans: readonly ScanMetricsRow[],
  vulnerabilities: readonly VulnerabilityMetricsRow[]
): Map<string, ProjectTelemetryAggregate> {
  const scanToProject = new Map<string, string>();
  const projectMap = new Map<string, ProjectTelemetryAggregate>();

  for (const scan of scans) {
    const projectName = scan.project_name;
    scanToProject.set(scan.id, projectName);

    let agg = projectMap.get(projectName);
    if (!agg) {
      agg = { scans: [], vulnerabilities: [] };
      projectMap.set(projectName, agg);
    }
    agg.scans.push(scan);
  }

  for (const vuln of vulnerabilities) {
    const projectName = scanToProject.get(vuln.scan_id);
    if (!projectName) continue;
    const agg = projectMap.get(projectName);
    if (agg) {
      agg.vulnerabilities.push(vuln);
    }
  }

  return projectMap;
}

function buildProjectSummaryFromTelemetry(
  projectName: string,
  agg: ProjectTelemetryAggregate | undefined,
  row?: ProjectRow
): DashboardProjectSummary {
  const projectScans = agg?.scans ?? [];
  const projectVulns = agg?.vulnerabilities ?? [];
  // Scans are already ordered newest-first.
  const latestScan = projectScans[0];
  const oldestScan = projectScans[projectScans.length - 1];

  const scoreReport = computeLiveSecurityScore(
    projectScans.length,
    projectVulns
  );

  const severityBreakdown = createEmptySeverityBreakdown();
  let openVulnerabilities = 0;
  let threatsFixed = 0;

  for (const vuln of projectVulns) {
    severityBreakdown[vuln.severity] += 1;
    if (vuln.status === "open") {
      openVulnerabilities += 1;
    } else if (vuln.status === "fixed") {
      threatsFixed += 1;
    }
  }

  const nowIso = new Date().toISOString();

  return {
    id: row?.id ?? slugifyProjectId(projectName),
    name: projectName,
    description: row?.description ?? null,
    repositoryUrl: row?.repository_url ?? null,
    language: row?.language ?? latestScan?.language ?? "unknown",
    scanCount: projectScans.length,
    latestScanId: latestScan?.id ?? null,
    latestScanAt: latestScan?.created_at ?? null,
    latestRiskScore: latestScan?.risk_score ?? 0,
    latestRiskGrade: latestScan?.risk_grade ?? "A",
    securityScore: scoreReport.score,
    letterGrade: scoreReport.letterGrade,
    openVulnerabilities,
    threatsFixed,
    severityBreakdown,
    createdAt: row?.created_at ?? oldestScan?.created_at ?? nowIso,
    updatedAt: row?.updated_at ?? latestScan?.created_at ?? nowIso,
  };
}

function buildLeaderboardEntries(
  scans: readonly ScanMetricsRow[],
  vulnerabilities: readonly VulnerabilityMetricsRow[],
  projectRows: readonly ProjectRow[],
  userProfile: {
    id: string;
    name: string;
  },
  scope: LeaderboardScope
): LeaderboardEntry[] {
  const entries: Omit<LeaderboardEntry, "rank">[] = [];
  const telemetryByProject = groupTelemetryByProject(scans, vulnerabilities);

  if (scope === "all" || scope === "projects") {
    const seenNames = new Set<string>();

    for (const project of projectRows) {
      seenNames.add(project.name);
      const agg = telemetryByProject.get(project.name);
      const projectScans = agg?.scans ?? [];
      const projectVulns = agg?.vulnerabilities ?? [];
      const report = computeLiveSecurityScore(
        projectScans.length,
        projectVulns
      );

      entries.push({
        id: project.id,
        name: project.name,
        type: "project",
        securityScore: report.score,
        letterGrade: report.letterGrade,
        securityLevel: report.securityLevel,
        developerLevel: report.developerLevel,
        scansCount: projectScans.length,
        threatsFixed: report.metrics.threatsFixed,
        openIssues: report.metrics.totalIssues,
        fixRatePercentage: report.metrics.fixRatePercentage,
        lastActivityAt: projectScans[0]?.created_at ?? project.updated_at,
      });
    }

    for (const [projectName, agg] of telemetryByProject.entries()) {
      if (seenNames.has(projectName)) continue;
      const report = computeLiveSecurityScore(
        agg.scans.length,
        agg.vulnerabilities
      );

      entries.push({
        id: slugifyProjectId(projectName),
        name: projectName,
        type: "project",
        securityScore: report.score,
        letterGrade: report.letterGrade,
        securityLevel: report.securityLevel,
        developerLevel: report.developerLevel,
        scansCount: agg.scans.length,
        threatsFixed: report.metrics.threatsFixed,
        openIssues: report.metrics.totalIssues,
        fixRatePercentage: report.metrics.fixRatePercentage,
        lastActivityAt: agg.scans[0]?.created_at ?? null,
      });
    }
  }

  if (scope === "all" || scope === "developers") {
    const devReport = computeLiveSecurityScore(scans.length, vulnerabilities);
    entries.push({
      id: userProfile.id,
      name: userProfile.name,
      type: "developer",
      securityScore: devReport.score,
      letterGrade: devReport.letterGrade,
      securityLevel: devReport.securityLevel,
      developerLevel: devReport.developerLevel,
      scansCount: scans.length,
      threatsFixed: devReport.metrics.threatsFixed,
      openIssues: devReport.metrics.totalIssues,
      fixRatePercentage: devReport.metrics.fixRatePercentage,
      lastActivityAt: scans[0]?.created_at ?? null,
    });
  }

  entries.sort(
    (a, b) =>
      b.securityScore - a.securityScore ||
      b.threatsFixed - a.threatsFixed ||
      b.scansCount - a.scansCount ||
      a.name.localeCompare(b.name)
  );

  return entries.map((entry, index) => ({
    ...entry,
    rank: index + 1,
  }));
}

/**
 * Query-optimized, Supabase-backed analytics & aggregation service for Sentinel AI Dashboards.
 */
export class DashboardService {
  /**
   * Returns the complete aggregated dashboard overview in a single parallel query wave.
   */
  public async getDashboardOverview(
    authCtx: AuthenticatedContext,
    query?: Partial<DashboardOverviewQueryParams>
  ): Promise<DashboardOverviewResponse> {
    const parsed = dashboardOverviewQuerySchema.parse(query ?? {});
    const { user, supabase } = authCtx;
    const extendedClient = getExtendedClient(supabase);
    const from = (parsed.page - 1) * parsed.pageSize;
    const to = from + parsed.pageSize - 1;

    let recentVulnsQuery = supabase
      .from("vulnerabilities")
      .select(
        "id, scan_id, rule_id, title, severity, category, cwe_id, owasp_category, confidence, line_start, line_end, status, created_at, updated_at",
        { count: "exact" }
      )
      .eq("user_id", user.id);

    if (parsed.severity !== undefined) {
      recentVulnsQuery = recentVulnsQuery.eq("severity", parsed.severity);
    }
    if (parsed.status !== undefined) {
      recentVulnsQuery = recentVulnsQuery.eq("status", parsed.status);
    }

    const [
      userRecord,
      projectsPageResult,
      recentScansResult,
      recentVulnsResult,
      timelineResult,
      allScansMetricsResult,
      allVulnsMetricsResult,
      profileResult,
    ] = await Promise.all([
      authService.getUserRecord(supabase, user),
      extendedClient
        .from("projects")
        .select(
          "id, user_id, name, description, repository_url, language, created_at, updated_at",
          { count: "exact" }
        )
        .eq("user_id", user.id)
        .order("updated_at", { ascending: false })
        .range(from, to),
      supabase
        .from("scans")
        .select(
          "id, project_name, file_name, language, status, risk_score, risk_grade, severity_breakdown, executed_rules_count, duration_ms, created_at",
          { count: "exact" }
        )
        .eq("user_id", user.id)
        .order("created_at", { ascending: false })
        .range(from, to),
      recentVulnsQuery
        .order("created_at", { ascending: false })
        .range(from, to),
      extendedClient
        .from("security_timeline")
        .select(
          "id, user_id, project_name, scan_id, timestamp, action, label, description, severity, status, metadata",
          { count: "exact" }
        )
        .eq("user_id", user.id)
        .order("timestamp", { ascending: false })
        .order("id", { ascending: false })
        .range(from, to),
      supabase
        .from("scans")
        .select(
          "id, project_name, file_name, language, risk_score, risk_grade, severity_breakdown, created_at"
        )
        .eq("user_id", user.id)
        .order("created_at", { ascending: false }),
      supabase
        .from("vulnerabilities")
        .select(
          "scan_id, rule_id, title, severity, category, status, created_at, updated_at"
        )
        .eq("user_id", user.id),
      supabase
        .from("profiles")
        .select("id, email, full_name, avatar_url")
        .eq("id", user.id)
        .maybeSingle(),
    ]);

    if (recentScansResult.error) {
      throw new InternalServerError(
        "Failed to load recent scans",
        recentScansResult.error.message
      );
    }
    if (recentVulnsResult.error) {
      throw new InternalServerError(
        "Failed to load recent vulnerabilities",
        recentVulnsResult.error.message
      );
    }
    if (allScansMetricsResult.error) {
      throw new InternalServerError(
        "Failed to load scan telemetry metrics",
        allScansMetricsResult.error.message
      );
    }
    if (allVulnsMetricsResult.error) {
      throw new InternalServerError(
        "Failed to load vulnerability telemetry metrics",
        allVulnsMetricsResult.error.message
      );
    }
    if (projectsPageResult.error && !isMissingTableError(projectsPageResult.error)) {
      throw new InternalServerError(
        "Failed to load dashboard projects",
        projectsPageResult.error.message
      );
    }
    if (timelineResult.error && !isMissingTableError(timelineResult.error)) {
      throw new InternalServerError(
        "Failed to load security timeline events",
        timelineResult.error.message
      );
    }

    const allScans = (allScansMetricsResult.data ?? []) as ScanMetricsRow[];
    const allVulns = (allVulnsMetricsResult.data ?? []) as VulnerabilityMetricsRow[];
    const projectRows = projectsPageResult.error
      ? []
      : ((projectsPageResult.data ?? []) as ProjectRow[]);
    const projectsTotal = projectsPageResult.error
      ? 0
      : (projectsPageResult.count ?? projectRows.length);

    const telemetryByProject = groupTelemetryByProject(allScans, allVulns);

    const projects: PaginatedCollection<DashboardProjectSummary> =
      projectsTotal > 0
        ? {
            items: projectRows.map((row) =>
              buildProjectSummaryFromTelemetry(
                row.name,
                telemetryByProject.get(row.name),
                row
              )
            ),
            pagination: buildPaginationMeta(
              parsed.page,
              parsed.pageSize,
              projectsTotal
            ),
          }
        : paginateArray(
            Array.from(telemetryByProject.entries())
              .map(([name, agg]) => buildProjectSummaryFromTelemetry(name, agg))
              .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)),
            parsed.page,
            parsed.pageSize
          );

    const recentScans: PaginatedCollection<DashboardScanSummary> = {
      items: ((recentScansResult.data ?? []) as ScanListRow[]).map(
        mapScanRowToSummary
      ),
      pagination: buildPaginationMeta(
        parsed.page,
        parsed.pageSize,
        recentScansResult.count ?? 0
      ),
    };

    const recentVulnerabilities: PaginatedCollection<DashboardVulnerabilitySummary> =
      {
        items: (
          (recentVulnsResult.data ?? []) as VulnerabilityListRow[]
        ).map(mapVulnerabilityRowToSummary),
        pagination: buildPaginationMeta(
          parsed.page,
          parsed.pageSize,
          recentVulnsResult.count ?? 0
        ),
      };

    const timeline: PaginatedCollection<TimelineEvent> = timelineResult.error
      ? {
          items: [],
          pagination: buildPaginationMeta(parsed.page, parsed.pageSize, 0),
        }
      : {
          items: ((timelineResult.data ?? []) as SecurityTimelineRow[]).map(
            mapTimelineRowToEvent
          ),
          pagination: buildPaginationMeta(
            parsed.page,
            parsed.pageSize,
            timelineResult.count ?? 0
          ),
        };

    const securityScore = computeLiveSecurityScore(allScans.length, allVulns);
    const threatStats = computeThreatStats(allVulns);
    const charts = buildChartsData(allScans, allVulns, threatStats);
    const monthlyActivity = buildMonthlyActivity(
      allScans,
      allVulns,
      parsed.months
    );

    const profileRow = profileResult.data as ProfileProjectionRow | null;
    const developerName =
      profileRow?.full_name?.trim() ||
      profileRow?.email ||
      userRecord.email ||
      "Developer";

    const rankedLeaderboard = buildLeaderboardEntries(
      allScans,
      allVulns,
      projectRows,
      { id: user.id, name: developerName },
      parsed.leaderboardScope
    );
    const leaderboard = paginateArray(
      rankedLeaderboard,
      parsed.page,
      parsed.pageSize
    );

    return {
      user: {
        id: userRecord.id,
        email: userRecord.email,
        created_at: userRecord.created_at,
        last_login: userRecord.last_login,
      },
      securityScore,
      projects,
      recentScans,
      recentVulnerabilities,
      timeline,
      threatStats,
      charts,
      monthlyActivity,
      leaderboard,
    };
  }

  /**
   * Returns paginated projects aggregated with scan counts and live risk/security scores.
   */
  public async getProjects(
    authCtx: AuthenticatedContext,
    query?: Partial<DashboardPaginationParams>
  ): Promise<PaginatedCollection<DashboardProjectSummary>> {
    const parsed = dashboardPaginationSchema.parse(query ?? {});
    const { user, supabase } = authCtx;
    const extendedClient = getExtendedClient(supabase);
    const from = (parsed.page - 1) * parsed.pageSize;
    const to = from + parsed.pageSize - 1;

    const [projectsPageResult, scansResult, vulnsResult] = await Promise.all([
      extendedClient
        .from("projects")
        .select(
          "id, user_id, name, description, repository_url, language, created_at, updated_at",
          { count: "exact" }
        )
        .eq("user_id", user.id)
        .order("updated_at", { ascending: false })
        .range(from, to),
      supabase
        .from("scans")
        .select(
          "id, project_name, file_name, language, risk_score, risk_grade, severity_breakdown, created_at"
        )
        .eq("user_id", user.id)
        .order("created_at", { ascending: false }),
      supabase
        .from("vulnerabilities")
        .select(
          "scan_id, rule_id, title, severity, category, status, created_at, updated_at"
        )
        .eq("user_id", user.id),
    ]);

    if (scansResult.error) {
      throw new InternalServerError(
        "Failed to load project scan metrics",
        scansResult.error.message
      );
    }
    if (vulnsResult.error) {
      throw new InternalServerError(
        "Failed to load project vulnerability metrics",
        vulnsResult.error.message
      );
    }
    if (projectsPageResult.error && !isMissingTableError(projectsPageResult.error)) {
      throw new InternalServerError(
        "Failed to load projects",
        projectsPageResult.error.message
      );
    }

    const scans = (scansResult.data ?? []) as ScanMetricsRow[];
    const vulns = (vulnsResult.data ?? []) as VulnerabilityMetricsRow[];
    const telemetryByProject = groupTelemetryByProject(scans, vulns);

    const projectRows = projectsPageResult.error
      ? []
      : ((projectsPageResult.data ?? []) as ProjectRow[]);
    const projectsTotal = projectsPageResult.error
      ? 0
      : (projectsPageResult.count ?? projectRows.length);

    if (projectsTotal > 0) {
      return {
        items: projectRows.map((row) =>
          buildProjectSummaryFromTelemetry(
            row.name,
            telemetryByProject.get(row.name),
            row
          )
        ),
        pagination: buildPaginationMeta(
          parsed.page,
          parsed.pageSize,
          projectsTotal
        ),
      };
    }

    const derived = Array.from(telemetryByProject.entries())
      .map(([name, agg]) => buildProjectSummaryFromTelemetry(name, agg))
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));

    return paginateArray(derived, parsed.page, parsed.pageSize);
  }

  /**
   * Returns paginated recent scans with minimal column projection (excludes `source_code`).
   */
  public async getRecentScans(
    authCtx: AuthenticatedContext,
    query?: Partial<DashboardPaginationParams>
  ): Promise<PaginatedCollection<DashboardScanSummary>> {
    const parsed = dashboardPaginationSchema.parse(query ?? {});
    const { user, supabase } = authCtx;
    const from = (parsed.page - 1) * parsed.pageSize;
    const to = from + parsed.pageSize - 1;

    const { data, error, count } = await supabase
      .from("scans")
      .select(
        "id, project_name, file_name, language, status, risk_score, risk_grade, severity_breakdown, executed_rules_count, duration_ms, created_at",
        { count: "exact" }
      )
      .eq("user_id", user.id)
      .order("created_at", { ascending: false })
      .range(from, to);

    if (error) {
      throw new InternalServerError(
        "Failed to load recent scans",
        error.message
      );
    }

    return {
      items: ((data ?? []) as ScanListRow[]).map(mapScanRowToSummary),
      pagination: buildPaginationMeta(parsed.page, parsed.pageSize, count ?? 0),
    };
  }

  /**
   * Returns paginated recent vulnerabilities with optional `severity`, `status`, and `scanId` filters.
   */
  public async getRecentVulnerabilities(
    authCtx: AuthenticatedContext,
    query?: Partial<DashboardVulnerabilitiesQueryParams>
  ): Promise<PaginatedCollection<DashboardVulnerabilitySummary>> {
    const parsed = dashboardVulnerabilitiesQuerySchema.parse(query ?? {});
    const { user, supabase } = authCtx;
    const from = (parsed.page - 1) * parsed.pageSize;
    const to = from + parsed.pageSize - 1;

    let dbQuery = supabase
      .from("vulnerabilities")
      .select(
        "id, scan_id, rule_id, title, severity, category, cwe_id, owasp_category, confidence, line_start, line_end, status, created_at, updated_at",
        { count: "exact" }
      )
      .eq("user_id", user.id);

    if (parsed.severity !== undefined) {
      dbQuery = dbQuery.eq("severity", parsed.severity);
    }
    if (parsed.status !== undefined) {
      dbQuery = dbQuery.eq("status", parsed.status);
    }
    if (parsed.scanId !== undefined) {
      dbQuery = dbQuery.eq("scan_id", parsed.scanId);
    }

    const { data, error, count } = await dbQuery
      .order("created_at", { ascending: false })
      .range(from, to);

    if (error) {
      throw new InternalServerError(
        "Failed to load recent vulnerabilities",
        error.message
      );
    }

    return {
      items: ((data ?? []) as VulnerabilityListRow[]).map(
        mapVulnerabilityRowToSummary
      ),
      pagination: buildPaginationMeta(parsed.page, parsed.pageSize, count ?? 0),
    };
  }

  /**
   * Returns threat statistics, chart datasets, and monthly activity for the last `months` months.
   */
  public async getChartsAndMonthlyActivity(
    authCtx: AuthenticatedContext,
    months = DEFAULT_MONTHS
  ): Promise<DashboardChartsResponse> {
    const parsed = dashboardChartsQuerySchema.parse({ months });
    const { user, supabase } = authCtx;

    const [scansResult, vulnsResult] = await Promise.all([
      supabase
        .from("scans")
        .select(
          "id, project_name, file_name, language, risk_score, risk_grade, severity_breakdown, created_at"
        )
        .eq("user_id", user.id)
        .order("created_at", { ascending: false }),
      supabase
        .from("vulnerabilities")
        .select(
          "scan_id, rule_id, title, severity, category, status, created_at, updated_at"
        )
        .eq("user_id", user.id),
    ]);

    if (scansResult.error) {
      throw new InternalServerError(
        "Failed to load scan chart data",
        scansResult.error.message
      );
    }
    if (vulnsResult.error) {
      throw new InternalServerError(
        "Failed to load vulnerability chart data",
        vulnsResult.error.message
      );
    }

    const scans = (scansResult.data ?? []) as ScanMetricsRow[];
    const vulns = (vulnsResult.data ?? []) as VulnerabilityMetricsRow[];

    const threatStats = computeThreatStats(vulns);
    const charts = buildChartsData(scans, vulns, threatStats);
    const monthlyActivity = buildMonthlyActivity(scans, vulns, parsed.months);

    return {
      months: parsed.months,
      threatStats,
      charts,
      monthlyActivity,
    };
  }

  /**
   * Returns paginated leaderboard entries ranking top projects and/or developers
   * by live security score and threats fixed.
   */
  public async getLeaderboard(
    authCtx: AuthenticatedContext,
    query?: Partial<DashboardLeaderboardQueryParams>
  ): Promise<PaginatedCollection<LeaderboardEntry>> {
    const parsed = dashboardLeaderboardQuerySchema.parse(query ?? {});
    const { user, supabase } = authCtx;
    const extendedClient = getExtendedClient(supabase);

    const [projectsResult, scansResult, vulnsResult, profileResult] =
      await Promise.all([
        extendedClient
          .from("projects")
          .select(
            "id, user_id, name, description, repository_url, language, created_at, updated_at"
          )
          .eq("user_id", user.id),
        supabase
          .from("scans")
          .select(
            "id, project_name, file_name, language, risk_score, risk_grade, severity_breakdown, created_at"
          )
          .eq("user_id", user.id)
          .order("created_at", { ascending: false }),
        supabase
          .from("vulnerabilities")
          .select(
            "scan_id, rule_id, title, severity, category, status, created_at, updated_at"
          )
          .eq("user_id", user.id),
        supabase
          .from("profiles")
          .select("id, email, full_name, avatar_url")
          .eq("id", user.id)
          .maybeSingle(),
      ]);

    if (scansResult.error) {
      throw new InternalServerError(
        "Failed to load leaderboard scan data",
        scansResult.error.message
      );
    }
    if (vulnsResult.error) {
      throw new InternalServerError(
        "Failed to load leaderboard vulnerability data",
        vulnsResult.error.message
      );
    }
    if (projectsResult.error && !isMissingTableError(projectsResult.error)) {
      throw new InternalServerError(
        "Failed to load leaderboard projects",
        projectsResult.error.message
      );
    }

    const projectRows = projectsResult.error
      ? []
      : ((projectsResult.data ?? []) as ProjectRow[]);
    const scans = (scansResult.data ?? []) as ScanMetricsRow[];
    const vulns = (vulnsResult.data ?? []) as VulnerabilityMetricsRow[];
    const profileRow = profileResult.data as ProfileProjectionRow | null;
    const developerName =
      profileRow?.full_name?.trim() ||
      profileRow?.email ||
      user.email ||
      "Developer";

    const ranked = buildLeaderboardEntries(
      scans,
      vulns,
      projectRows,
      { id: user.id, name: developerName },
      parsed.scope
    );

    return paginateArray(ranked, parsed.page, parsed.pageSize);
  }
}

export const dashboardService = new DashboardService();
