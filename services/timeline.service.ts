import { z } from "zod";
import {
  TimelineRepository,
  type SecurityTimelineInsert,
} from "@/database/repositories/timeline.repository";
import {
  authService,
  type AuthenticatedContext,
} from "@/services/auth.service";
import {
  TIMELINE_ACTION_DEFAULT_SEVERITY,
  TIMELINE_ACTION_DEFAULT_STATUS,
  TIMELINE_ACTION_LABELS,
  TIMELINE_ACTIONS,
  TIMELINE_ORDERS,
  TIMELINE_SEVERITIES,
  TIMELINE_STATUSES,
  type CreateTimelineEventInput,
  type OrderedTimelineResponse,
  type TimelineEvent,
  type TimelineQueryOptions,
} from "@/types/timeline.types";

const DEFAULT_PAGE = 1;
const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 100;
const MAX_BATCH_SIZE = 100;

export const timelineActionSchema = z.enum(TIMELINE_ACTIONS);
export const timelineSeveritySchema = z.enum(TIMELINE_SEVERITIES);
export const timelineStatusSchema = z.enum(TIMELINE_STATUSES);
export const timelineOrderSchema = z.enum(TIMELINE_ORDERS);

export const createTimelineEventSchema = z.object({
  projectName: z
    .string()
    .trim()
    .min(1, "projectName is required")
    .max(200, "projectName must be 200 characters or fewer"),
  scanId: z
    .string()
    .uuid("scanId must be a valid UUID")
    .nullable()
    .optional(),
  timestamp: z
    .string()
    .datetime({ offset: true, message: "timestamp must be a valid ISO-8601 datetime" })
    .optional(),
  action: timelineActionSchema,
  label: z
    .string()
    .trim()
    .min(1, "label cannot be empty")
    .max(160, "label must be 160 characters or fewer")
    .optional(),
  description: z
    .string()
    .trim()
    .max(2000, "description must be 2000 characters or fewer")
    .nullable()
    .optional(),
  severity: timelineSeveritySchema.optional(),
  status: timelineStatusSchema.optional(),
  metadata: z.record(z.unknown()).optional(),
});

export const createTimelineEventsSchema = z
  .array(createTimelineEventSchema)
  .min(1, "At least one timeline event is required")
  .max(MAX_BATCH_SIZE, `A maximum of ${MAX_BATCH_SIZE} events may be logged per batch`);

export const timelineQueryOptionsSchema = z.object({
  projectName: z
    .string()
    .trim()
    .min(1, "projectName cannot be empty")
    .max(200, "projectName must be 200 characters or fewer")
    .optional(),
  scanId: z.string().uuid("scanId must be a valid UUID").optional(),
  action: timelineActionSchema.optional(),
  severity: timelineSeveritySchema.optional(),
  order: timelineOrderSchema.default("asc"),
  page: z.coerce
    .number()
    .int("page must be an integer")
    .min(1, "page must be at least 1")
    .default(DEFAULT_PAGE),
  pageSize: z.coerce
    .number()
    .int("pageSize must be an integer")
    .min(1, "pageSize must be at least 1")
    .max(MAX_PAGE_SIZE, `pageSize must be ${MAX_PAGE_SIZE} or fewer`)
    .default(DEFAULT_PAGE_SIZE),
});

function buildInsertPayload(
  userId: string,
  parsed: z.infer<typeof createTimelineEventSchema>
): SecurityTimelineInsert {
  const description =
    parsed.description !== undefined && parsed.description !== null && parsed.description.length > 0
      ? parsed.description
      : null;

  return {
    user_id: userId,
    project_name: parsed.projectName,
    scan_id: parsed.scanId ?? null,
    ...(parsed.timestamp !== undefined ? { timestamp: parsed.timestamp } : {}),
    action: parsed.action,
    label: parsed.label ?? TIMELINE_ACTION_LABELS[parsed.action],
    description,
    severity: parsed.severity ?? TIMELINE_ACTION_DEFAULT_SEVERITY[parsed.action],
    status: parsed.status ?? TIMELINE_ACTION_DEFAULT_STATUS[parsed.action],
    metadata: parsed.metadata ?? {},
  };
}

/**
 * Security Timeline Service responsible for validating, persisting, and querying
 * ordered security lifecycle events for authenticated Sentinel AI users.
 */
export class TimelineService {
  private async resolveContext(
    context?: AuthenticatedContext
  ): Promise<AuthenticatedContext> {
    if (context) {
      return context;
    }
    return authService.requireAuthenticatedUser();
  }

  /**
   * Validates and logs a single security timeline event for the authenticated user.
   */
  public async logEvent(
    input: CreateTimelineEventInput,
    context?: AuthenticatedContext
  ): Promise<TimelineEvent> {
    const parsed = createTimelineEventSchema.parse(input);
    const { user, supabase } = await this.resolveContext(context);
    const repository = new TimelineRepository(supabase);

    return repository.create(buildInsertPayload(user.id, parsed));
  }

  /**
   * Validates and logs a batch of security timeline events for the authenticated user.
   */
  public async logEvents(
    inputs: CreateTimelineEventInput[],
    context?: AuthenticatedContext
  ): Promise<TimelineEvent[]> {
    const parsedList = createTimelineEventsSchema.parse(inputs);
    const { user, supabase } = await this.resolveContext(context);
    const repository = new TimelineRepository(supabase);

    const payloads = parsedList.map((item) => buildInsertPayload(user.id, item));
    return repository.createMany(payloads);
  }

  /**
   * Returns an ordered, paginated security timeline with severity breakdown
   * for the authenticated user.
   */
  public async getOrderedTimeline(
    options: TimelineQueryOptions = {},
    context?: AuthenticatedContext
  ): Promise<OrderedTimelineResponse> {
    const parsed = timelineQueryOptionsSchema.parse(options);
    const { user, supabase } = await this.resolveContext(context);
    const repository = new TimelineRepository(supabase);

    const filters = {
      ...(parsed.projectName !== undefined
        ? { projectName: parsed.projectName }
        : {}),
      ...(parsed.scanId !== undefined ? { scanId: parsed.scanId } : {}),
      ...(parsed.action !== undefined ? { action: parsed.action } : {}),
      ...(parsed.severity !== undefined ? { severity: parsed.severity } : {}),
    };

    const [{ items, total }, severityBreakdown] = await Promise.all([
      repository.listOrdered(user.id, {
        ...filters,
        order: parsed.order,
        page: parsed.page,
        pageSize: parsed.pageSize,
      }),
      repository.countBySeverity(user.id, filters),
    ]);

    const totalPages = total === 0 ? 0 : Math.ceil(total / parsed.pageSize);

    return {
      events: items,
      order: parsed.order,
      total,
      pagination: {
        page: parsed.page,
        pageSize: parsed.pageSize,
        total,
        totalPages,
      },
      severityBreakdown,
      filters: {
        projectName: parsed.projectName ?? null,
        scanId: parsed.scanId ?? null,
        action: parsed.action ?? null,
        severity: parsed.severity ?? null,
      },
    };
  }
}

export const timelineService = new TimelineService();
