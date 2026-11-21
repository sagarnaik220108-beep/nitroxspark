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
 * GET /api/dashboard/projects
 * Protected paginated projects endpoint returning projects aggregated with
 * scan counts, latest risk score, and live calculated security score.
 */
export const GET = withAuth(async (request, auth) => {
  const { searchParams } = request.nextUrl;

  const validatedQuery = dashboardPaginationSchema.parse({
    page: readOptionalParam(searchParams, "page"),
    pageSize: readOptionalParam(searchParams, "pageSize"),
  });

  const result = await dashboardService.getProjects(auth, validatedQuery);

  return apiSuccess(result.items, 200, result.pagination, {
    "Cache-Control": "no-store",
  });
});
