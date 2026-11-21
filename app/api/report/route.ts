import type { NextRequest } from "next/server";
import { reportService } from "@/services/report.service";
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
 * GET /api/report
 * Returns a paginated list of persisted security reports for the authenticated user.
 */
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = request.nextUrl;
    const { reports, pagination } = await reportService.listUserReports({
      page: readOptionalParam(searchParams, "page"),
      pageSize: readOptionalParam(searchParams, "pageSize"),
    });

    return apiSuccess({ reports }, 200, pagination, {
      "Cache-Control": "no-store",
    });
  } catch (error) {
    return handleRouteError(error);
  }
}

/**
 * POST /api/report
 * Generates and persists a new security report for an existing scan.
 * Returns 201 Created.
 */
export async function POST(request: NextRequest) {
  try {
    let rawBody: unknown;
    try {
      rawBody = await request.json();
    } catch {
      throw new ValidationError("Request body must be valid JSON");
    }

    const report = await reportService.generateReport(rawBody);

    return apiSuccess(report, 201, undefined, {
      "Cache-Control": "no-store",
    });
  } catch (error) {
    return handleRouteError(error);
  }
}
