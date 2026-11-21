import { z } from "zod";
import { analyzeCode } from "@/security/analyzer";
import {
  apiSuccess,
  handleRouteError,
  supportedLanguageSchema,
  ValidationError,
} from "@/utils";

const analyzeRequestSchema = z.object({
  code: z.string().min(1, "Source code cannot be empty"),
  fileName: z
    .string()
    .trim()
    .min(1, "File name cannot be empty")
    .max(255, "File name must be 255 characters or fewer")
    .optional(),
  language: supportedLanguageSchema.optional(),
  enabledRuleIds: z.array(z.string().trim().min(1)).optional(),
  disabledRuleIds: z.array(z.string().trim().min(1)).optional(),
});

/**
 * POST /api/analyze
 * Analyzes submitted source code against the Sentinel AI modular security rule registry
 * and returns a single structured JSON vulnerability report.
 */
export async function POST(request: Request) {
  try {
    let rawBody: unknown;
    try {
      rawBody = await request.json();
    } catch {
      throw new ValidationError("Request body must be valid JSON");
    }

    const parsed = analyzeRequestSchema.parse(rawBody);

    const report = analyzeCode(parsed.code, {
      fileName: parsed.fileName,
      language: parsed.language,
      enabledRuleIds: parsed.enabledRuleIds,
      disabledRuleIds: parsed.disabledRuleIds,
    });

    return apiSuccess(report, 200);
  } catch (error) {
    return handleRouteError(error);
  }
}
