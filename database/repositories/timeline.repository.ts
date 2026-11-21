import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database, SeverityBreakdown } from "@/types";
import type {
  TimelineAction,
  TimelineEvent,
  TimelineOrder,
  TimelineSeverity,
  TimelineStatus,
} from "@/types/timeline.types";
import { InternalServerError } from "@/utils";

/**
 * Strongly-typed row shape for `public.security_timeline` (migration `002_security_timeline.sql`).
 */
export type SecurityTimelineRow = {
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
};

export type SecurityTimelineInsert = {
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

export type SecurityTimelineUpdate = {
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

/**
 * Local typed Supabase schema view for `public.security_timeline` so
 * `TimelineRepository` remains strictly typed without mutating shared schema files.
 */
export interface TimelineTableSchema {
  public: {
    Tables: {
      security_timeline: {
        Row: SecurityTimelineRow;
        Insert: SecurityTimelineInsert;
        Update: SecurityTimelineUpdate;
        Relationships: [];
      };
    };
    Views: Record<string, never>;
    Functions: Record<string, never>;
    Enums: Record<string, never>;
    CompositeTypes: Record<string, never>;
  };
}

export interface TimelineFilterParams {
  projectName?: string;
  scanId?: string;
  action?: TimelineAction;
  severity?: TimelineSeverity;
}

export interface TimelineListOrderedParams extends TimelineFilterParams {
  order: TimelineOrder;
  page: number;
  pageSize: number;
}

function toTimelineClient(
  db: SupabaseClient<Database> | SupabaseClient<TimelineTableSchema>
): SupabaseClient<TimelineTableSchema> {
  return db as unknown as SupabaseClient<TimelineTableSchema>;
}

function normalizeMetadata(value: unknown): Record<string, unknown> {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
}

function mapRowToTimelineEvent(row: SecurityTimelineRow): TimelineEvent {
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

/**
 * Data access repository for `public.security_timeline`.
 * All queries are scoped to `user_id` in addition to enforcing Supabase RLS.
 */
export class TimelineRepository {
  private readonly db: SupabaseClient<TimelineTableSchema>;

  constructor(
    supabase: SupabaseClient<Database> | SupabaseClient<TimelineTableSchema>
  ) {
    this.db = toTimelineClient(supabase);
  }

  /**
   * Inserts a single security timeline event and returns the persisted domain model.
   */
  public async create(payload: SecurityTimelineInsert): Promise<TimelineEvent> {
    const { data, error } = await this.db
      .from("security_timeline")
      .insert(payload)
      .select("*")
      .single();

    if (error || !data) {
      throw new InternalServerError(
        "Failed to persist security timeline event",
        error?.message
      );
    }

    return mapRowToTimelineEvent(data);
  }

  /**
   * Inserts multiple security timeline events in a single batch and returns them.
   */
  public async createMany(
    payloads: SecurityTimelineInsert[]
  ): Promise<TimelineEvent[]> {
    if (payloads.length === 0) {
      return [];
    }

    const { data, error } = await this.db
      .from("security_timeline")
      .insert(payloads)
      .select("*");

    if (error) {
      throw new InternalServerError(
        "Failed to persist security timeline events",
        error.message
      );
    }

    return (data ?? []).map(mapRowToTimelineEvent);
  }

  /**
   * Lists ordered security timeline events for the given user with optional
   * filtering and pagination.
   */
  public async listOrdered(
    userId: string,
    params: TimelineListOrderedParams
  ): Promise<{ items: TimelineEvent[]; total: number }> {
    const from = (params.page - 1) * params.pageSize;
    const to = from + params.pageSize - 1;
    const ascending = params.order === "asc";

    let query = this.db
      .from("security_timeline")
      .select("*", { count: "exact" })
      .eq("user_id", userId);

    if (params.projectName !== undefined) {
      query = query.eq("project_name", params.projectName);
    }
    if (params.scanId !== undefined) {
      query = query.eq("scan_id", params.scanId);
    }
    if (params.action !== undefined) {
      query = query.eq("action", params.action);
    }
    if (params.severity !== undefined) {
      query = query.eq("severity", params.severity);
    }

    const { data, error, count } = await query
      .order("timestamp", { ascending })
      .order("id", { ascending })
      .range(from, to);

    if (error) {
      throw new InternalServerError(
        "Failed to query security timeline events",
        error.message
      );
    }

    return {
      items: (data ?? []).map(mapRowToTimelineEvent),
      total: count ?? 0,
    };
  }

  /**
   * Aggregates timeline event counts grouped by severity for the given user
   * and optional filter criteria.
   */
  public async countBySeverity(
    userId: string,
    filters: TimelineFilterParams = {}
  ): Promise<SeverityBreakdown> {
    let query = this.db
      .from("security_timeline")
      .select("severity")
      .eq("user_id", userId);

    if (filters.projectName !== undefined) {
      query = query.eq("project_name", filters.projectName);
    }
    if (filters.scanId !== undefined) {
      query = query.eq("scan_id", filters.scanId);
    }
    if (filters.action !== undefined) {
      query = query.eq("action", filters.action);
    }
    if (filters.severity !== undefined) {
      query = query.eq("severity", filters.severity);
    }

    const { data, error } = await query;

    if (error) {
      throw new InternalServerError(
        "Failed to aggregate timeline severity counts",
        error.message
      );
    }

    const breakdown: SeverityBreakdown = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    for (const row of data ?? []) {
      breakdown[row.severity] += 1;
    }

    return breakdown;
  }
}
