import type { PaginationMeta } from "./api.types";
import type { Severity, SeverityBreakdown } from "./security.types";

/**
 * All supported security lifecycle timeline actions in Sentinel AI.
 */
export const TIMELINE_ACTIONS = [
  "PROJECT_CREATED",
  "ANALYSIS_STARTED",
  "API_KEY_FOUND",
  "SQL_INJECTION_FOUND",
  "FIX_APPLIED",
  "ATTACK_SIMULATED",
  "REPORT_GENERATED",
  "DEPLOYMENT_APPROVED",
] as const;

export type TimelineAction = (typeof TIMELINE_ACTIONS)[number];

/**
 * Human-readable labels for every security timeline event action.
 */
export const TIMELINE_ACTION_LABELS: Readonly<Record<TimelineAction, string>> = {
  PROJECT_CREATED: "Project Created",
  ANALYSIS_STARTED: "Analysis Started",
  API_KEY_FOUND: "API Key Found",
  SQL_INJECTION_FOUND: "SQL Injection Found",
  FIX_APPLIED: "Fix Applied",
  ATTACK_SIMULATED: "Attack Simulated",
  REPORT_GENERATED: "Report Generated",
  DEPLOYMENT_APPROVED: "Deployment Approved",
};

/**
 * Supported severity levels for timeline events.
 */
export const TIMELINE_SEVERITIES = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
] as const;

export type TimelineSeverity = Severity;

/**
 * Supported lifecycle statuses for timeline events.
 */
export const TIMELINE_STATUSES = [
  "pending",
  "in_progress",
  "completed",
  "warning",
  "blocked",
  "approved",
] as const;

export type TimelineStatus = (typeof TIMELINE_STATUSES)[number];

/**
 * Chronological ordering direction for timeline queries.
 */
export const TIMELINE_ORDERS = ["asc", "desc"] as const;

export type TimelineOrder = (typeof TIMELINE_ORDERS)[number];

/**
 * Default severity associated with each timeline action when not explicitly provided.
 */
export const TIMELINE_ACTION_DEFAULT_SEVERITY: Readonly<
  Record<TimelineAction, TimelineSeverity>
> = {
  PROJECT_CREATED: "info",
  ANALYSIS_STARTED: "info",
  API_KEY_FOUND: "critical",
  SQL_INJECTION_FOUND: "critical",
  FIX_APPLIED: "low",
  ATTACK_SIMULATED: "high",
  REPORT_GENERATED: "info",
  DEPLOYMENT_APPROVED: "info",
};

/**
 * Default status associated with each timeline action when not explicitly provided.
 */
export const TIMELINE_ACTION_DEFAULT_STATUS: Readonly<
  Record<TimelineAction, TimelineStatus>
> = {
  PROJECT_CREATED: "completed",
  ANALYSIS_STARTED: "in_progress",
  API_KEY_FOUND: "warning",
  SQL_INJECTION_FOUND: "warning",
  FIX_APPLIED: "completed",
  ATTACK_SIMULATED: "completed",
  REPORT_GENERATED: "completed",
  DEPLOYMENT_APPROVED: "approved",
};

/**
 * Domain model representing a single security timeline event persisted in Supabase.
 */
export interface TimelineEvent {
  id: string;
  userId: string;
  projectName: string;
  scanId: string | null;
  timestamp: string;
  action: TimelineAction;
  label: string;
  description: string | null;
  severity: TimelineSeverity;
  status: TimelineStatus;
  metadata: Record<string, unknown>;
}

/**
 * Input contract for logging a new security timeline event.
 */
export interface CreateTimelineEventInput {
  projectName: string;
  scanId?: string | null;
  timestamp?: string;
  action: TimelineAction;
  label?: string;
  description?: string | null;
  severity?: TimelineSeverity;
  status?: TimelineStatus;
  metadata?: Record<string, unknown>;
}

/**
 * Filter, sorting, and pagination options for querying an ordered timeline.
 */
export interface TimelineQueryOptions {
  projectName?: string;
  scanId?: string;
  action?: TimelineAction;
  severity?: TimelineSeverity;
  order?: TimelineOrder;
  page?: number;
  pageSize?: number;
}

/**
 * Ordered timeline response payload returned by the Timeline Service and API.
 */
export interface OrderedTimelineResponse {
  events: TimelineEvent[];
  order: TimelineOrder;
  total: number;
  pagination: PaginationMeta;
  severityBreakdown: SeverityBreakdown;
  filters: {
    projectName: string | null;
    scanId: string | null;
    action: TimelineAction | null;
    severity: TimelineSeverity | null;
  };
}
