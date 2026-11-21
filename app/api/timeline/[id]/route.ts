import type { SupabaseClient } from "@supabase/supabase-js";
import { z } from "zod";
import { withAuth } from "@/lib/auth/middleware";
import type { SupabaseServerClient } from "@/services/auth.service";
import {
  TIMELINE_SEVERITIES,
  TIMELINE_STATUSES,
  type TimelineAction,
  type TimelineEvent,
  type TimelineSeverity,
  type TimelineStatus,
} from "@/types/timeline.types";
import {
  apiSuccess,
  InternalServerError,
  NotFoundError,
  parseOrThrow,
  uuidParamSchema,
  ValidationError,
} from "@/utils";

type SecurityTimelineRow = {
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

type SecurityTimelineUpdate = {
  description?: string | null;
  severity?: TimelineSeverity;
  status?: TimelineStatus;
};

/**
 * Local typed Supabase schema view for `public.security_timeline`
 * (migration `002_security_timeline.sql`).
 */
interface TimelineTableSchema {
  public: {
    Tables: {
      security_timeline: {
        Row: SecurityTimelineRow;
        Insert: never;
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

const updateTimelineEventSchema = z
  .object({
    status: z.enum(TIMELINE_STATUSES).optional(),
    severity: z.enum(TIMELINE_SEVERITIES).optional(),
    description: z
      .string()
      .trim()
      .max(2000, "description must be 2000 characters or fewer")
      .nullable()
      .optional(),
  })
  .refine(
    (data) =>
      data.status !== undefined ||
      data.severity !== undefined ||
      data.description !== undefined,
    {
      message:
        "At least one of status, severity, or description must be provided",
    }
  );

function getTimelineClient(
  supabase: SupabaseServerClient
): SupabaseClient<TimelineTableSchema> {
  return supabase as unknown as SupabaseClient<TimelineTableSchema>;
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
 * GET /api/timeline/[id]
 * Retrieves a single security timeline event owned by the authenticated user.
 */
export const GET = withAuth<{ id: string }>(async (_request, auth, context) => {
  const { id } = await context.params;
  const validId = parseOrThrow(uuidParamSchema, id);
  const timelineClient = getTimelineClient(auth.supabase);

  const { data, error } = await timelineClient
    .from("security_timeline")
    .select("*")
    .eq("id", validId)
    .eq("user_id", auth.user.id)
    .maybeSingle();

  if (error) {
    throw new InternalServerError(
      "Failed to fetch security timeline event",
      error.message
    );
  }
  if (!data) {
    throw new NotFoundError("TimelineEvent", validId);
  }

  return apiSuccess(mapRowToTimelineEvent(data), 200, undefined, {
    "Cache-Control": "no-store",
  });
});

/**
 * PUT /api/timeline/[id]
 * Updates `status`, `severity`, and/or `description` of a timeline event owned by the user.
 */
export const PUT = withAuth<{ id: string }>(async (request, auth, context) => {
  const { id } = await context.params;
  const validId = parseOrThrow(uuidParamSchema, id);

  let rawBody: unknown;
  try {
    rawBody = await request.json();
  } catch {
    throw new ValidationError("Request body must be valid JSON");
  }

  const input = parseOrThrow(updateTimelineEventSchema, rawBody);
  const timelineClient = getTimelineClient(auth.supabase);

  const updatePayload: SecurityTimelineUpdate = {};
  if (input.status !== undefined) {
    updatePayload.status = input.status;
  }
  if (input.severity !== undefined) {
    updatePayload.severity = input.severity;
  }
  if (input.description !== undefined) {
    updatePayload.description =
      input.description !== null && input.description.length > 0
        ? input.description
        : null;
  }

  const { data, error } = await timelineClient
    .from("security_timeline")
    .update(updatePayload)
    .eq("id", validId)
    .eq("user_id", auth.user.id)
    .select("*")
    .maybeSingle();

  if (error) {
    throw new InternalServerError(
      "Failed to update security timeline event",
      error.message
    );
  }
  if (!data) {
    throw new NotFoundError("TimelineEvent", validId);
  }

  return apiSuccess(mapRowToTimelineEvent(data), 200, undefined, {
    "Cache-Control": "no-store",
  });
});

/**
 * DELETE /api/timeline/[id]
 * Deletes a security timeline event owned by the authenticated user.
 */
export const DELETE = withAuth<{ id: string }>(
  async (_request, auth, context) => {
    const { id } = await context.params;
    const validId = parseOrThrow(uuidParamSchema, id);
    const timelineClient = getTimelineClient(auth.supabase);

    const { data, error } = await timelineClient
      .from("security_timeline")
      .delete()
      .eq("id", validId)
      .eq("user_id", auth.user.id)
      .select("id")
      .maybeSingle();

    if (error) {
      throw new InternalServerError(
        "Failed to delete security timeline event",
        error.message
      );
    }
    if (!data) {
      throw new NotFoundError("TimelineEvent", validId);
    }

    return apiSuccess({ deletedId: validId }, 200, undefined, {
      "Cache-Control": "no-store",
    });
  }
);
