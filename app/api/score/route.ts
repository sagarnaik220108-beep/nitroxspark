import type { NextRequest } from "next/server";
import { scoreService } from "@/services/score.service";
import { apiSuccess, handleRouteError } from "@/utils/api-response";
import { ValidationError } from "@/utils/errors";

export const runtime = "nodejs";

/**
 * GET /api/score
 * Computes and returns the live security posture score for the authenticated
 * user by aggregating their `scans` and `vulnerabilities` in Supabase.
 */
export async function GET() {
  try {
    const report = await scoreService.calculateForAuthenticatedUser();
    return apiSuccess(report, 200, undefined, { "Cache-Control": "no-store" });
  } catch (error) {
    return handleRouteError(error);
  }
}

/**
 * POST /api/score
 * Calculates a security posture score report from a submitted JSON metrics
 * payload without requiring database persistence.
 */
export async function POST(request: NextRequest) {
  try {
    let rawBody: unknown;
    try {
      rawBody = await request.json();
    } catch {
      throw new ValidationError("Request body must be valid JSON");
    }

    if (!rawBody || typeof rawBody !== "object" || Array.isArray(rawBody)) {
      throw new ValidationError(
        "Request body must be a JSON object containing security metrics"
      );
    }

    const report = scoreService.calculateFromInput(rawBody);
    return apiSuccess(report, 200);
  } catch (error) {
    return handleRouteError(error);
  }
}
