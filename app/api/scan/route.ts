import type { NextRequest } from "next/server";
import { scanService } from "@/services/scan.service";
import { apiSuccess, handleRouteError, ValidationError } from "@/utils";

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
 * GET /api/scan
 * Returns a paginated list of scans for the authenticated user.
 */
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = request.nextUrl;
    const { scans, pagination } = await scanService.listUserScans({
      page: readOptionalParam(searchParams, "page"),
      pageSize: readOptionalParam(searchParams, "pageSize"),
    });

    return apiSuccess({ scans }, 200, pagination, {
      "Cache-Control": "no-store",
    });
  } catch (error) {
    return handleRouteError(error);
  }
}

/**
 * POST /api/scan
 * Creates and runs a new static security scan for the authenticated user.
 * Returns 201 Created with the persisted scan and detected vulnerabilities.
 */
export async function POST(request: NextRequest) {
  try {
    let rawBody: unknown;
    try {
      rawBody = await request.json();
    } catch {
      throw new ValidationError("Request body must be valid JSON");
    }

    const result = await scanService.createAndRunScan(rawBody);

    return apiSuccess(result, 201, undefined, {
      "Cache-Control": "no-store",
    });
  } catch (error) {
    return handleRouteError(error);
  }
}
