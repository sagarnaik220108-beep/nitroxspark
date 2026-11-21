import type { NextRequest } from "next/server";
import { z } from "zod";
import { uploadScanService } from "@/services/upload-scan.service";
import { apiSuccess, handleRouteError, ValidationError } from "@/utils";

const urlUploadSchema = z.object({
  url: z
    .string({ required_error: "A URL string is required" })
    .trim()
    .min(1, "URL cannot be empty")
    .max(2048, "URL exceeds maximum length of 2048 characters"),
});

/**
 * POST /api/upload
 * Accepts either:
 *  - `multipart/form-data` with a `file` field (up to 256 KB source/config file)
 *  - `application/json` with `{ url: "https://..." }` (SSRF-protected remote scan)
 */
export async function POST(request: NextRequest) {
  try {
    const contentType = (request.headers.get("content-type") ?? "").toLowerCase();

    if (contentType.includes("multipart/form-data")) {
      let formData: FormData;
      try {
        formData = await request.formData();
      } catch {
        throw new ValidationError("Invalid multipart/form-data payload.");
      }

      const fileEntry = formData.get("file");
      if (!(fileEntry instanceof File)) {
        throw new ValidationError(
          "A file must be uploaded in the 'file' form field."
        );
      }

      const result = await uploadScanService.scanUploadedFile(fileEntry);
      return apiSuccess(result, 200, undefined, {
        "Cache-Control": "no-store",
      });
    }

    if (contentType.includes("application/json")) {
      let rawBody: unknown;
      try {
        rawBody = await request.json();
      } catch {
        throw new ValidationError("Request body must be valid JSON.");
      }

      const parsed = urlUploadSchema.parse(rawBody);
      const result = await uploadScanService.scanUrl(parsed.url);
      return apiSuccess(result, 200, undefined, {
        "Cache-Control": "no-store",
      });
    }

    throw new ValidationError(
      "Unsupported Content-Type. Send 'multipart/form-data' with a file or 'application/json' with { url }."
    );
  } catch (error) {
    return handleRouteError(error);
  }
}
