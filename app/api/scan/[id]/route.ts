import type { NextRequest } from "next/server";
import { z } from "zod";
import type { Database } from "@/types";
import { AuditRepository } from "@/database/repositories";
import { withAuth } from "@/lib/auth/middleware";
import { scanService } from "@/services/scan.service";
import {
  apiSuccess,
  handleRouteError,
  InternalServerError,
  NotFoundError,
  parseOrThrow,
  uuidParamSchema,
  ValidationError,
} from "@/utils";

const scanStatusSchema = z.enum(["pending", "processing", "completed", "failed"]);

const updateScanMetadataSchema = z
  .object({
    projectName: z
      .string()
      .trim()
      .min(1, "projectName cannot be empty")
      .max(120, "projectName must be 120 characters or fewer")
      .optional(),
    fileName: z
      .string()
      .trim()
      .min(1, "fileName cannot be empty")
      .max(255, "fileName must be 255 characters or fewer")
      .optional(),
    status: scanStatusSchema.optional(),
  })
  .refine(
    (data) =>
      data.projectName !== undefined ||
      data.fileName !== undefined ||
      data.status !== undefined,
    {
      message: "At least one of projectName, fileName, or status must be provided",
    }
  );

type ScanUpdate = Database["public"]["Tables"]["scans"]["Update"];

/**
 * GET /api/scan/[id]
 * Retrieves a scan and its associated vulnerabilities for the authenticated user.
 */
export async function GET(
  _request: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await context.params;
    const result = await scanService.getScanById(id);

    return apiSuccess(result, 200, undefined, {
      "Cache-Control": "no-store",
    });
  } catch (error) {
    return handleRouteError(error);
  }
}

/**
 * PUT /api/scan/[id]
 * Updates scan metadata (`projectName`, `fileName`, `status`) for a scan owned by the user.
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

  const input = parseOrThrow(updateScanMetadataSchema, rawBody);

  const updatePayload: ScanUpdate = {
    updated_at: new Date().toISOString(),
  };

  if (input.projectName !== undefined) {
    updatePayload.project_name = input.projectName;
  }
  if (input.fileName !== undefined) {
    updatePayload.file_name = input.fileName;
  }
  if (input.status !== undefined) {
    updatePayload.status = input.status;
  }

  const { data, error } = await auth.supabase
    .from("scans")
    .update(updatePayload)
    .eq("id", validId)
    .eq("user_id", auth.user.id)
    .select("*")
    .maybeSingle();

  if (error) {
    throw new InternalServerError("Failed to update scan", error.message);
  }
  if (!data) {
    throw new NotFoundError("Scan", validId);
  }

  const auditRepo = new AuditRepository(auth.supabase);
  await auditRepo.record({
    userId: auth.user.id,
    action: "scan.updated",
    resourceType: "scan",
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
 * DELETE /api/scan/[id]
 * Deletes a scan owned by the authenticated user.
 */
export async function DELETE(
  _request: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await context.params;
    const result = await scanService.deleteScan(id);

    return apiSuccess(result, 200, undefined, {
      "Cache-Control": "no-store",
    });
  } catch (error) {
    return handleRouteError(error);
  }
}
