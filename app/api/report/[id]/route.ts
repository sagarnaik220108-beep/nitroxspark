import type { NextRequest } from "next/server";
import { z } from "zod";
import type { Database } from "@/types";
import { AuditRepository } from "@/database/repositories";
import { withAuth } from "@/lib/auth/middleware";
import { reportService } from "@/services/report.service";
import {
  apiSuccess,
  handleRouteError,
  InternalServerError,
  NotFoundError,
  parseOrThrow,
  uuidParamSchema,
  ValidationError,
} from "@/utils";

const updateReportSchema = z
  .object({
    title: z
      .string()
      .trim()
      .min(1, "Report title cannot be empty")
      .max(200, "Report title must be 200 characters or fewer")
      .optional(),
    format: z.enum(["json", "markdown"]).optional(),
  })
  .refine((data) => data.title !== undefined || data.format !== undefined, {
    message: "At least one of title or format must be provided",
  });

type ReportUpdate = Database["public"]["Tables"]["security_reports"]["Update"];

/**
 * GET /api/report/[id]
 * Retrieves a single persisted security report owned by the authenticated user.
 */
export async function GET(
  _request: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await context.params;
    const report = await reportService.getReportById(id);

    return apiSuccess(report, 200, undefined, {
      "Cache-Control": "no-store",
    });
  } catch (error) {
    return handleRouteError(error);
  }
}

/**
 * PUT /api/report/[id]
 * Updates a report's `title` and/or `format` for a report owned by the authenticated user.
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

  const input = parseOrThrow(updateReportSchema, rawBody);

  const updatePayload: ReportUpdate = {};
  if (input.title !== undefined) {
    updatePayload.title = input.title;
  }
  if (input.format !== undefined) {
    updatePayload.format = input.format;
  }

  const { data, error } = await auth.supabase
    .from("security_reports")
    .update(updatePayload)
    .eq("id", validId)
    .eq("user_id", auth.user.id)
    .select("*")
    .maybeSingle();

  if (error) {
    throw new InternalServerError(
      "Failed to update security report",
      error.message
    );
  }
  if (!data) {
    throw new NotFoundError("SecurityReport", validId);
  }

  const auditRepo = new AuditRepository(auth.supabase);
  await auditRepo.record({
    userId: auth.user.id,
    action: "report.updated",
    resourceType: "security_report",
    resourceId: data.id,
    metadata: {
      updatedFields: Object.keys(input),
    },
  });

  return apiSuccess(data, 200, undefined, {
    "Cache-Control": "no-store",
  });
});

/**
 * DELETE /api/report/[id]
 * Deletes a persisted security report owned by the authenticated user.
 */
export async function DELETE(
  _request: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await context.params;
    const result = await reportService.deleteReport(id);

    return apiSuccess(result, 200, undefined, {
      "Cache-Control": "no-store",
    });
  } catch (error) {
    return handleRouteError(error);
  }
}
