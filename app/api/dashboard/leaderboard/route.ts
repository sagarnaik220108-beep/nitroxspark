import { withAuth } from "@/lib/auth/middleware";
import {
  dashboardLeaderboardQuerySchema,
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
 * GET /api/dashboard/leaderboard
 * Protected paginated leaderboard endpoint ranking top projects and developers
 * by live security score and threats fixed.
 */
export const GET = withAuth(async (request, auth) => {
  const { searchParams } = request.nextUrl;

  const validatedQuery = dashboardLeaderboardQuerySchema.parse({
    page: readOptionalParam(searchParams, "page"),
    pageSize: readOptionalParam(searchParams, "pageSize"),
    scope: readOptionalParam(searchParams, "scope"),
  });

  const result = await dashboardService.getLeaderboard(auth, validatedQuery);

  return apiSuccess(result.items, 200, result.pagination, {
    "Cache-Control": "no-store",
  });
});
