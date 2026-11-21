import { z } from "zod";
import { defaultFileTargetAttackSimulator } from "@/security/simulator/file-target-simulator";
import {
  apiSuccess,
  handleRouteError,
  supportedLanguageSchema,
  ValidationError,
} from "@/utils";

const structuredVulnSchema = z.object({
  ruleId: z.string(),
  name: z.string(),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  category: z.enum([
    "injection",
    "xss",
    "secrets",
    "authentication",
    "authorization",
    "ssrf",
    "path-traversal",
    "cryptography",
    "misconfiguration",
    "deserialization",
    "other",
  ]),
  cweId: z.string(),
  owaspCategory: z.string(),
  description: z.string(),
  risk: z.string(),
  fileLine: z.number().int().min(1),
  column: z.number().int().min(1).default(1),
  snippet: z.string(),
  suggestedFix: z.string(),
  secureCodeExample: z.string(),
  confidenceScore: z.number().min(0).max(1).default(0.85),
});

const fileAttackRequestSchema = z.object({
  code: z.string().min(1, "Source code is required for file attack simulation"),
  fileName: z.string().trim().min(1).default("uploaded-file.ts"),
  language: supportedLanguageSchema.optional(),
  vulnerabilities: z.array(structuredVulnSchema).optional(),
});

/**
 * POST /api/attack/file
 * Runs 100% simulated before-vs-after attack simulations directly against the
 * user's own uploaded/active file and its detected vulnerabilities.
 */
export async function POST(request: Request) {
  try {
    let rawBody: unknown;
    try {
      rawBody = await request.json();
    } catch {
      throw new ValidationError("Request body must be valid JSON");
    }

    const parsed = fileAttackRequestSchema.parse(rawBody);
    const result = defaultFileTargetAttackSimulator.run({
      code: parsed.code,
      fileName: parsed.fileName,
      language: parsed.language,
      vulnerabilities: parsed.vulnerabilities,
    });

    return apiSuccess(result, 200, undefined, {
      "Cache-Control": "no-store",
    });
  } catch (error) {
    return handleRouteError(error);
  }
}
