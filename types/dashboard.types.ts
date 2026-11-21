import type { PaginationMeta } from "./api.types";
import type {
  DeveloperLevel,
  LetterGrade,
  SecurityLevel,
  SecurityScoreReport,
} from "./score.types";
import type {
  ScanStatus,
  Severity,
  SeverityBreakdown,
  SupportedLanguage,
  VulnerabilityCategory,
  VulnerabilityStatus,
} from "./security.types";
import type { TimelineEvent } from "./timeline.types";

/**
 * Common pagination query parameters for Dashboard API endpoints.
 */
export interface DashboardPaginationParams {
  page: number;
  pageSize: number;
}

/**
 * Filterable pagination parameters for `GET /api/dashboard/vulnerabilities`.
 */
export interface DashboardVulnerabilitiesQueryParams
  extends DashboardPaginationParams {
  severity?: Severity;
  status?: VulnerabilityStatus;
  scanId?: string;
}

/**
 * Supported leaderboard ranking scopes.
 */
export type LeaderboardScope = "all" | "projects" | "developers";

/**
 * Query parameters for `GET /api/dashboard/leaderboard`.
 */
export interface DashboardLeaderboardQueryParams
  extends DashboardPaginationParams {
  scope: LeaderboardScope;
}

/**
 * Query parameters for `GET /api/dashboard` overview endpoint.
 */
export interface DashboardOverviewQueryParams extends DashboardPaginationParams {
  months: number;
  severity?: Severity;
  status?: VulnerabilityStatus;
  leaderboardScope: LeaderboardScope;
}

/**
 * Standardized paginated collection wrapper for dashboard sub-resources.
 */
export interface PaginatedCollection<T> {
  items: T[];
  pagination: PaginationMeta;
}

/**
 * Authenticated user summary returned in the dashboard overview.
 */
export interface DashboardUserSummary {
  id: string;
  email: string;
  created_at: string;
  last_login: string;
}

/**
 * Aggregated project summary enriched with scan counts and live risk/security scores.
 */
export interface DashboardProjectSummary {
  id: string;
  name: string;
  description: string | null;
  repositoryUrl: string | null;
  language: SupportedLanguage;
  scanCount: number;
  latestScanId: string | null;
  latestScanAt: string | null;
  latestRiskScore: number;
  latestRiskGrade: "A" | "B" | "C" | "D" | "F";
  securityScore: number;
  letterGrade: LetterGrade;
  openVulnerabilities: number;
  threatsFixed: number;
  severityBreakdown: SeverityBreakdown;
  createdAt: string;
  updatedAt: string;
}

/**
 * Lightweight scan projection (excludes heavy `source_code` column).
 */
export interface DashboardScanSummary {
  id: string;
  projectName: string;
  fileName: string;
  language: SupportedLanguage;
  status: ScanStatus;
  riskScore: number;
  riskGrade: "A" | "B" | "C" | "D" | "F";
  severityBreakdown: SeverityBreakdown;
  executedRulesCount: number;
  durationMs: number;
  createdAt: string;
}

/**
 * Lightweight vulnerability projection for dashboard tables and feeds.
 */
export interface DashboardVulnerabilitySummary {
  id: string;
  scanId: string;
  ruleId: string;
  title: string;
  severity: Severity;
  category: VulnerabilityCategory;
  cweId: string;
  owaspCategory: string;
  confidence: number;
  lineStart: number;
  lineEnd: number;
  status: VulnerabilityStatus;
  createdAt: string;
  updatedAt: string;
}

/**
 * Ranked category count entry in threat statistics.
 */
export interface TopCategoryStat {
  category: VulnerabilityCategory;
  label: string;
  count: number;
  percentage: number;
}

/**
 * Ranked rule count entry in threat statistics.
 */
export interface TopRuleStat {
  ruleId: string;
  title: string;
  severity: Severity;
  count: number;
}

/**
 * Aggregate threat and remediation statistics across the user's scans.
 */
export interface DashboardThreatStats {
  totalDetected: number;
  open: number;
  acknowledged: number;
  fixed: number;
  falsePositive: number;
  severityBreakdown: SeverityBreakdown;
  fixRatePercentage: number;
  topCategories: TopCategoryStat[];
  topRules: TopRuleStat[];
}

/**
 * Single datum for severity distribution charts.
 */
export interface SeverityDistributionDatum {
  severity: Severity;
  label: string;
  count: number;
  percentage: number;
}

/**
 * Single datum for vulnerability category breakdown charts.
 */
export interface CategoryBreakdownDatum {
  category: VulnerabilityCategory;
  label: string;
  count: number;
  percentage: number;
}

/**
 * Chronological data point for scan risk/security score trend charts.
 */
export interface ScanRiskTrendPoint {
  scanId: string;
  projectName: string;
  fileName: string;
  riskScore: number;
  securityScore: number;
  riskGrade: "A" | "B" | "C" | "D" | "F";
  totalFindings: number;
  createdAt: string;
}

/**
 * Chart-ready datasets for dashboard visualizations.
 */
export interface DashboardChartsData {
  severityDistribution: SeverityDistributionDatum[];
  categoryBreakdown: CategoryBreakdownDatum[];
  scanRiskTrend: ScanRiskTrendPoint[];
}

/**
 * Monthly security telemetry point grouped by UTC `YYYY-MM`.
 */
export interface MonthlyActivityPoint {
  month: string;
  scansCount: number;
  vulnerabilitiesFound: number;
  threatsFixed: number;
  avgRiskScore: number;
}

/**
 * Response payload for `GET /api/dashboard/charts`.
 */
export interface DashboardChartsResponse {
  months: number;
  threatStats: DashboardThreatStats;
  charts: DashboardChartsData;
  monthlyActivity: MonthlyActivityPoint[];
}

/**
 * Ranked leaderboard entry for top projects and developers.
 */
export interface LeaderboardEntry {
  rank: number;
  id: string;
  name: string;
  type: "project" | "developer";
  securityScore: number;
  letterGrade: LetterGrade;
  securityLevel: SecurityLevel;
  developerLevel: DeveloperLevel;
  scansCount: number;
  threatsFixed: number;
  openIssues: number;
  fixRatePercentage: number;
  lastActivityAt: string | null;
}

/**
 * Complete aggregated payload returned by `GET /api/dashboard`.
 */
export interface DashboardOverviewResponse {
  user: DashboardUserSummary;
  securityScore: SecurityScoreReport;
  projects: PaginatedCollection<DashboardProjectSummary>;
  recentScans: PaginatedCollection<DashboardScanSummary>;
  recentVulnerabilities: PaginatedCollection<DashboardVulnerabilitySummary>;
  timeline: PaginatedCollection<TimelineEvent>;
  threatStats: DashboardThreatStats;
  charts: DashboardChartsData;
  monthlyActivity: MonthlyActivityPoint[];
  leaderboard: PaginatedCollection<LeaderboardEntry>;
}
