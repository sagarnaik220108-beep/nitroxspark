import { withAuth } from "@/lib/auth/middleware";
import {
  dashboardPaginationSchema,
  dashboardService,
} from "@/services/dashboard.service";
import { apiSuccess } from "@/utils";

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
 * GET /api/dashboard/scans
 * Protected paginated recent scans endpoint using minimal column projections.
 */
export const GET = withAuth(async (request, auth) => {
  const { searchParams } = request.nextUrl;

  const validatedQuery = dashboardPaginationSchema.parse({
    page: readOptionalParam(searchParams, "page"),
    pageSize: readOptionalParam(searchParams, "pageSize"),
  });

  const result = await dashboardService.getRecentScans(auth, validatedQuery);

  return apiSuccess(result.items, 200, result.pagination, {
    "Cache-Control": "no-store",
  });
});
