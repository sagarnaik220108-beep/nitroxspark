import type { NextRequest } from "next/server";
import { simulationEngineService } from "@/services/simulation-engine.service";
import { apiSuccess, handleRouteError, ValidationError } from "@/utils";

/**
 * GET /api/attack
 * Lists all available 100% simulated Before-vs-After attack scenarios.
 */
export async function GET() {
  try {
    const catalog = simulationEngineService.listScenarios();
    return apiSuccess(catalog, 200, undefined, {
      "Cache-Control": "no-store",
    });
  } catch (error) {
    return handleRouteError(error);
  }
}

/**
 * POST /api/attack
 * Executes 100% simulated Before-vs-After attack scenario(s).
 * Accepts JSON body `{ attackType?, attackTypes?, codeContext? }`:
 * - `attackType`: runs a single scenario
 * - `attackTypes`: runs multiple specified scenarios
 * - omitted / empty object: runs all built-in scenarios
 */
export async function POST(request: NextRequest) {
  try {
    const rawText = await request.text();
    let body: unknown = {};

    if (rawText.trim().length > 0) {
      try {
        body = JSON.parse(rawText) as unknown;
      } catch {
        throw new ValidationError("Request body must be valid JSON");
      }
    }

    const result = simulationEngineService.executeSimulationRequest(body);
    return apiSuccess(result, 200, undefined, {
      "Cache-Control": "no-store",
    });
  } catch (error) {
    return handleRouteError(error);
  }
}
