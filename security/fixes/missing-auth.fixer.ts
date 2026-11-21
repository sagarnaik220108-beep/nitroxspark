import type {
  FixVulnerabilityInput,
  SecureFixInput,
  SecureFixResult,
  VulnerabilityFixer,
} from "@/types/fix.types";
import {
  buildFixResult,
  getIndentation,
} from "./base";

const SUPPORTED_RULE_IDS = [
  "SENTINEL-AUTH-002",
  "MISSING-AUTHORIZATION",
  "MISSING-AUTH",
  "UNPROTECTED-ROUTE",
] as const;

/**
 * Deterministic Non-AI Fixer for Missing Authorization on sensitive routes.
 * Injects `requireAuth` middleware into unauthenticated Express/Next.js route handlers
 * or prepends session authorization verification checks.
 */
export const missingAuthFixer: VulnerabilityFixer = {
  id: "sentinel-missing-auth-fixer",
  name: "Authorization Guard Injector",
  description:
    "Injects requireAuth middleware or session checks into sensitive route handlers lacking access control.",
  supportedRuleIds: SUPPORTED_RULE_IDS,
  supportedCategories: ["authorization", "authentication"],

  canHandle(vulnerability: FixVulnerabilityInput): boolean {
    const ruleIdUpper = vulnerability.ruleId.toUpperCase();
    if (SUPPORTED_RULE_IDS.some((id) => ruleIdUpper.includes(id))) {
      return true;
    }
    const title = (vulnerability.title ?? vulnerability.name ?? "").toLowerCase();
    const desc = (vulnerability.description ?? "").toLowerCase();
    return (
      (vulnerability.category === "authorization" || vulnerability.category === "authentication") &&
      (title.includes("authorization") || desc.includes("authorization") || title.includes("unprotected") || ruleIdUpper.includes("AUTH"))
    );
  },

  apply(input: SecureFixInput): SecureFixResult {
    const { originalCode, vulnerability } = input;
    let secureCode = originalCode;
    let fixSummary = "Injected authorization middleware guard into route handler.";

    // 1. Check if Express app.delete / app.post / app.put lacks middleware
    const expressRouteRegex = /\b(app|router)\.(delete|post|put|patch)\s*\(\s*(['"`][^'"`]+['"`])\s*,\s*(async\s*)?\(/i;
    if (expressRouteRegex.test(secureCode)) {
      // Check if requireAuth definition already exists in file
      let helperPrefix = "";
      if (!secureCode.includes("requireAuth")) {
        helperPrefix = `// Sentinel Automated Invariant: Enforce authentication middleware\nfunction requireAuth(req: any, res: any, next: any) {\n  const token = req.headers.authorization;\n  if (!token) return res.status(401).json({ error: 'Unauthorized: Missing authorization header' });\n  next();\n}\n\n`;
      }

      secureCode = helperPrefix + secureCode.replace(
        expressRouteRegex,
        `$1.$2($3, requireAuth, $4(`
      );
      fixSummary = "Injected requireAuth middleware guard into sensitive Express/Node route handler.";
    }
    // 2. Next.js App Router export async function DELETE/POST/PUT without auth
    else if (/export\s+(async\s+)?function\s+(POST|PUT|PATCH|DELETE)\s*\([^)]*\)\s*\{/i.test(secureCode)) {
      secureCode = secureCode.replace(
        /(export\s+(?:async\s+)?function\s+(?:POST|PUT|PATCH|DELETE)\s*\([^)]*\)\s*\{)/i,
        `$1\n  // Sentinel Invariant: Verify session authorization\n  const session = await auth();\n  if (!session?.user) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });`
      );
      fixSummary = "Injected session authentication check into Next.js route handler.";
    }
    // 3. Fallback: replace allowAll: true or skipAuthorization: true
    else if (/\b(allowAll|skipAuthorization|disableRbac)\s*[:=]\s*true\b/i.test(secureCode)) {
      secureCode = secureCode.replace(
        /\b(allowAll|skipAuthorization|disableRbac)\s*[:=]\s*true\b/gi,
        "$1: false"
      );
      fixSummary = "Disabled insecure bypass flag (set to false).";
    }

    return buildFixResult(
      originalCode,
      secureCode,
      this.id,
      vulnerability.severity,
      fixSummary
    );
  },
};
