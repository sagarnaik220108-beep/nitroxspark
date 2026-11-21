import { defaultFixerRegistry, defaultRuleRegistry } from "@/security";
import { apiSuccess } from "@/utils";

/**
 * GET /api/health
 * Public liveness and readiness probe for Vercel and monitoring.
 */
export async function GET() {
  return apiSuccess({
    status: "healthy",
    service: "sentinel-ai",
    version: "1.0.0",
    engines: {
      securityRulesLoaded: defaultRuleRegistry.listAll().length,
      secureFixersLoaded: defaultFixerRegistry.listRegisteredFixers().length,
    },
  });
}
