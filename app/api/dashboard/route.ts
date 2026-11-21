import { withAuth } from "@/lib/auth/middleware";
import {
  dashboardOverviewQuerySchema,
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
 * GET /api/dashboard
 * Protected aggregated dashboard overview endpoint returning:
 * - Authenticated user summary
 * - Live calculated Security Score (`calculateSecurityScore`)
 * - Paginated Projects (aggregated with scan counts & risk/security scores)
 * - Paginated Recent Scans
 * - Paginated Recent Vulnerabilities (optionally filtered by `severity` & `status`)
 * - Paginated Security Timeline events
 * - Threat Statistics
 * - Chart Datasets (severity distribution, category breakdown, scan risk trend)
 * - Monthly Activity (last N months grouped by `YYYY-MM`, default 12)
 * - Paginated Leaderboard (projects & developers)
 */
export const GET = withAuth(async (request, auth) => {
  const { searchParams } = request.nextUrl;

  const validatedQuery = dashboardOverviewQuerySchema.parse({
    page: readOptionalParam(searchParams, "page"),
    pageSize: readOptionalParam(searchParams, "pageSize"),
    months: readOptionalParam(searchParams, "months"),
    severity: readOptionalParam(searchParams, "severity"),
    status: readOptionalParam(searchParams, "status"),
    leaderboardScope: readOptionalParam(searchParams, "leaderboardScope"),
  });

  const overview = await dashboardService.getDashboardOverview(
    auth,
    validatedQuery
  );

  return apiSuccess(overview, 200, overview.recentScans.pagination, {
    "Cache-Control": "no-store",
  });
});
