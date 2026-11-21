import { withAuth } from "@/lib/auth/middleware";
import {
  dashboardService,
  dashboardVulnerabilitiesQuerySchema,
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
 * GET /api/dashboard/vulnerabilities
 * Protected paginated vulnerabilities endpoint filterable by `severity`, `status`, and `scanId`.
 */
export const GET = withAuth(async (request, auth) => {
  const { searchParams } = request.nextUrl;

  const validatedQuery = dashboardVulnerabilitiesQuerySchema.parse({
    page: readOptionalParam(searchParams, "page"),
    pageSize: readOptionalParam(searchParams, "pageSize"),
    severity: readOptionalParam(searchParams, "severity"),
    status: readOptionalParam(searchParams, "status"),
    scanId: readOptionalParam(searchParams, "scanId"),
  });

  const result = await dashboardService.getRecentVulnerabilities(
    auth,
    validatedQuery
  );

  return apiSuccess(result.items, 200, result.pagination, {
    "Cache-Control": "no-store",
  });
});
