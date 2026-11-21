import { withAuth } from "@/lib/auth/middleware";
import {
  dashboardChartsQuerySchema,
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
 * GET /api/dashboard/charts
 * Protected analytics endpoint returning threat statistics, chart datasets
 * (severity distribution, category breakdown, scan risk trend), and monthly activity.
 */
export const GET = withAuth(async (request, auth) => {
  const { searchParams } = request.nextUrl;

  const validatedQuery = dashboardChartsQuerySchema.parse({
    months: readOptionalParam(searchParams, "months"),
  });

  const result = await dashboardService.getChartsAndMonthlyActivity(
    auth,
    validatedQuery.months
  );

  return apiSuccess(result, 200, undefined, {
    "Cache-Control": "no-store",
  });
});
