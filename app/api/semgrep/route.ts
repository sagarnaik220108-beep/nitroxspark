import { semgrepService } from "@/services/semgrep.service";
import { apiSuccess, handleRouteError, ValidationError } from "@/utils";

export const runtime = "nodejs";

/**
 * GET /api/semgrep
 * Returns Semgrep engine status, CLI availability, active mode, and supported rulesets.
 */
export async function GET() {
  try {
    const status = await semgrepService.getStatus();
    return apiSuccess(status, 200);
  } catch (error) {
    return handleRouteError(error);
  }
}

/**
 * POST /api/semgrep
 * Runs the Semgrep security engine (CLI when available, built-in Semgrep rule pack fallback),
 * optionally merging and deduplicating findings with Sentinel AI's core rule engine.
 */
export async function POST(request: Request) {
  try {
    let rawBody: unknown;
    try {
      rawBody = await request.json();
    } catch {
      throw new ValidationError("Request body must be valid JSON");
    }

    const result = await semgrepService.scanCode(rawBody);
    return apiSuccess(result, 200);
  } catch (error) {
    return handleRouteError(error);
  }
}
