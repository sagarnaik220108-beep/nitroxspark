import { withAuth } from "@/lib/auth/middleware";
import {
  timelineQueryOptionsSchema,
  timelineService,
} from "@/services/timeline.service";
import type { CreateTimelineEventInput } from "@/types/timeline.types";
import { apiSuccess, ValidationError } from "@/utils";

function readOptionalParam(
  searchParams: URLSearchParams,
  key: string
): string | undefined {
  const value = searchParams.get(key);
  if (value === null) return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * GET /api/timeline
 * Returns the authenticated user's ordered security timeline.
 * Query parameters:
 * - `projectName`: filter by project name
 * - `scanId`: filter by scan UUID
 * - `action`: filter by one of the 8 timeline actions
 * - `severity`: filter by severity (`critical | high | medium | low | info`)
 * - `order`: `asc` (default, chronological) or `desc` (reverse-chronological)
 * - `page`: 1-based page number (default `1`)
 * - `pageSize`: events per page (default `50`, max `100`)
 */
export const GET = withAuth(async (request, auth) => {
  const { searchParams } = request.nextUrl;

  const rawQuery = {
    projectName: readOptionalParam(searchParams, "projectName"),
    scanId: readOptionalParam(searchParams, "scanId"),
    action: readOptionalParam(searchParams, "action"),
    severity: readOptionalParam(searchParams, "severity"),
    order: readOptionalParam(searchParams, "order"),
    page: readOptionalParam(searchParams, "page"),
    pageSize: readOptionalParam(searchParams, "pageSize"),
  };

  const validatedQuery = timelineQueryOptionsSchema.parse(rawQuery);
  const timeline = await timelineService.getOrderedTimeline(
    validatedQuery,
    auth
  );

  return apiSuccess(timeline, 200, timeline.pagination, {
    "Cache-Control": "no-store",
  });
});

/**
 * POST /api/timeline
 * Logs a new security timeline event for the authenticated user and returns 201 JSON.
 */
export const POST = withAuth(async (request, auth) => {
  let rawBody: unknown;
  try {
    rawBody = await request.json();
  } catch {
    throw new ValidationError("Request body must be valid JSON");
  }

  const createdEvent = await timelineService.logEvent(
    rawBody as CreateTimelineEventInput,
    auth
  );

  return apiSuccess(createdEvent, 201, undefined, {
    "Cache-Control": "no-store",
  });
});
