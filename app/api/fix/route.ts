import { NextRequest } from "next/server";
import { fixService } from "@/services/fix.service";
import { apiSuccess, handleRouteError } from "@/utils/api-response";
import { ValidationError } from "@/utils/errors";

/**
 * GET /api/fix
 * Lists all registered pluggable vulnerability fixers available in Sentinel AI.
 */
export async function GET() {
  try {
    const fixers = fixService.listAvailableFixers();
    return apiSuccess({ fixers }, 200);
  } catch (error) {
    return handleRouteError(error);
  }
}

/**
 * POST /api/fix
 * Transforms vulnerable code into secure code and quantifies risk reduction.
 * Accepts either:
 *   - `{ originalCode: string, vulnerability: FixVulnerabilityInput }`
 *   - `{ originalCode: string, vulnerabilities: FixVulnerabilityInput[] }`
 */
export async function POST(request: NextRequest) {
  try {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      throw new ValidationError("Request body must be valid JSON");
    }

    const result = fixService.processFixRequest(body);
    return apiSuccess(result, 200);
  } catch (error) {
    return handleRouteError(error);
  }
}
