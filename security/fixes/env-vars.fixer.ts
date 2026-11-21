import type {
  FixVulnerabilityInput,
  SecureFixInput,
  SecureFixResult,
  VulnerabilityFixer,
} from "@/types/fix.types";
import {
  buildFixResult,
  getIndentation,
  normalizeVulnerabilitySearchText,
} from "./base";

const SUPPORTED_RULE_IDS = [
  "SENTINEL-ENV-001",
  "ENV-VARS",
  "ENV-EXPOSURE",
  "NEXT-PUBLIC-SECRET",
  "PROCESS-ENV-LEAK",
] as const;

const SENSITIVE_ENV_SUFFIX_REGEX =
  /(?:SECRET|KEY|TOKEN|PASSWORD|PASSWD|PRIVATE|AUTH|CREDENTIAL|DATABASE|DB_|SERVICE_ROLE|SIGNING|JWT|WEBHOOK)/i;

/**
 * Fixer 8: Exposed Environment Variables & Server Secrets
 * - Strips the `NEXT_PUBLIC_` prefix from server-only secrets so Next.js does not bundle them into client JS
 * - Removes `console.log(process.env)` / debug dumps of `process.env`
 * - Replaces raw `process.env` serialization in API responses (`res.json(process.env)`, `NextResponse.json(process.env)`, `JSON.stringify(process.env)`)
 */
export const envVarsFixer: VulnerabilityFixer = {
  id: "fixer-env-vars",
  name: "Environment Variable Exposure Fixer",
  description:
    "Removes NEXT_PUBLIC_ prefixes from server secrets and strips raw process.env logging or HTTP response leaks.",
  supportedRuleIds: SUPPORTED_RULE_IDS,
  supportedCategories: ["secrets", "misconfiguration"],

  canHandle(vulnerability: FixVulnerabilityInput): boolean {
    const text = normalizeVulnerabilitySearchText(vulnerability);
    if (
      SUPPORTED_RULE_IDS.some(
        (id) => id.toLowerCase() === vulnerability.ruleId.trim().toLowerCase()
      )
    ) {
      return true;
    }
    return (
      text.includes("next_public_") ||
      text.includes("process.env") ||
      text.includes("env var") ||
      text.includes("environment variable") ||
      text.includes("env exposure") ||
      text.includes("cwe-200") ||
      text.includes("cwe-497")
    );
  },

  apply(input: SecureFixInput): SecureFixResult {
    const { originalCode, vulnerability } = input;
    const lines = originalCode.split(/\r?\n/);
    const updatedLines: string[] = [];
    const actions: string[] = [];

    for (const line of lines) {
      const indent = getIndentation(line);

      // 1. Strip console.log / console.info / console.debug / console.warn / console.error dumping process.env
      if (
        /\bconsole\.(?:log|info|debug|warn|error|dir)\s*\([^)]*\bprocess\.env\b(?![.[])[^)]*\)/.test(
          line
        )
      ) {
        updatedLines.push(
          `${indent}// Removed raw process.env logging to prevent server secret exposure`
        );
        actions.push("Stripped raw process.env console logging");
        continue;
      }

      let nextLine = line;

      // 2. Remove NEXT_PUBLIC_ prefix from server secrets in process.env.NEXT_PUBLIC_*
      nextLine = nextLine.replace(
        /\bprocess\.env\.NEXT_PUBLIC_([A-Z0-9_]+)\b/g,
        (fullMatch, suffix: string) => {
          if (SENSITIVE_ENV_SUFFIX_REGEX.test(suffix)) {
            actions.push(`Removed NEXT_PUBLIC_ prefix from ${suffix}`);
            return `process.env.${suffix}`;
          }
          return fullMatch;
        }
      );

      // 3. Remove NEXT_PUBLIC_ prefix in .env-style assignments: NEXT_PUBLIC_STRIPE_SECRET_KEY=...
      nextLine = nextLine.replace(
        /^(\s*)NEXT_PUBLIC_([A-Z0-9_]+)(\s*=)/,
        (fullMatch, lead: string, suffix: string, eq: string) => {
          if (SENSITIVE_ENV_SUFFIX_REGEX.test(suffix)) {
            actions.push(`Removed NEXT_PUBLIC_ prefix from ${suffix}`);
            return `${lead}${suffix}${eq}`;
          }
          return fullMatch;
        }
      );

      // 4. Prevent raw process.env returned in HTTP responses: NextResponse.json(process.env) / res.json(process.env)
      nextLine = nextLine.replace(
        /\b(NextResponse\.json|res\.json|Response\.json|res\.send)\s*\(\s*process\.env\s*\)/g,
        (_m, fnCall: string) => {
          actions.push("Replaced raw process.env response with safe allowlisted payload");
          return `${fnCall}({ status: "ok", environment: process.env.NODE_ENV ?? "production" })`;
        }
      );

      // 5. Prevent raw process.env nested in response object: { env: process.env }
      nextLine = nextLine.replace(
        /(\b[a-zA-Z_$][\w$]*\s*:\s*)process\.env\b(?![.[])/g,
        (_m, propPrefix: string) => {
          actions.push("Replaced raw process.env object property with safe NODE_ENV field");
          return `${propPrefix}{ nodeEnv: process.env.NODE_ENV ?? "production" }`;
        }
      );

      // 6. Prevent JSON.stringify(process.env)
      nextLine = nextLine.replace(
        /\bJSON\.stringify\s*\(\s*process\.env(?:\s*,[^)]*)?\)/g,
        () => {
          actions.push("Replaced JSON.stringify(process.env) with safe NODE_ENV serialization");
          return `JSON.stringify({ nodeEnv: process.env.NODE_ENV ?? "production" })`;
        }
      );

      updatedLines.push(nextLine);
    }

    const secureCode = updatedLines.join("\n");
    const uniqueActions = Array.from(new Set(actions));
    const summaryText =
      uniqueActions.length > 0
        ? uniqueActions.join("; ") + "."
        : "Secured environment variable handling to prevent client-side or response secret exposure.";

    return buildFixResult({
      fixerId: this.id,
      originalCode,
      secureCode,
      severity: vulnerability.severity,
      reason: summaryText,
      summary: summaryText,
      rationale:
        "Prevents server-only secrets from being inlined into browser bundles via NEXT_PUBLIC_ or leaked through logs and HTTP responses.",
    });
  },
};
