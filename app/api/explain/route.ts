import type { NextRequest } from "next/server";
import { z } from "zod";
import {
  batchExplanationInputSchema,
  explanationService,
  vulnerabilityExplanationInputSchema,
} from "@/services/explanation.service";
import { apiSuccess, handleRouteError } from "@/utils/api-response";
import { ValidationError } from "@/utils/errors";

export const runtime = "nodejs";

const singleExplainRequestSchema = z
  .object({
    vulnerability: vulnerabilityExplanationInputSchema,
    useAI: z.boolean().optional(),
  })
  .strict();

const batchExplainRequestSchema = z
  .object({
    vulnerabilities: batchExplanationInputSchema,
    useAI: z.boolean().optional(),
  })
  .strict();

/**
 * GET /api/explain
 * Returns metadata for all curated beginner-friendly explanation templates.
 */
export async function GET() {
  try {
    const templates = explanationService.listSupportedTemplates();
    return apiSuccess({
      total: templates.length,
      templates,
    });
  } catch (error) {
    return handleRouteError(error);
  }
}

/**
 * POST /api/explain
 * Generates beginner-friendly vulnerability explanations.
 *
 * Accepts either:
 * - `{ "vulnerability": { ... }, "useAI"?: boolean }`
 * - `{ "vulnerabilities": [ ... ], "useAI"?: boolean }`
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
        "Request body must be a JSON object containing either 'vulnerability' or 'vulnerabilities'"
      );
    }

    const bodyRecord = rawBody as Record<string, unknown>;
    const hasSingle = "vulnerability" in bodyRecord;
    const hasBatch = "vulnerabilities" in bodyRecord;

    if (hasSingle && hasBatch) {
      throw new ValidationError(
        "Provide either 'vulnerability' or 'vulnerabilities', not both"
      );
    }

    if (hasBatch) {
      const parsed = batchExplainRequestSchema.parse(rawBody);
      const result = await explanationService.explainMany(
        parsed.vulnerabilities,
        { useAI: parsed.useAI }
      );
      return apiSuccess(result);
    }

    if (hasSingle) {
      const parsed = singleExplainRequestSchema.parse(rawBody);
      const explanation = await explanationService.explain(
        parsed.vulnerability,
        { useAI: parsed.useAI }
      );
      return apiSuccess({ explanation });
    }

    throw new ValidationError(
      "Request body must include either 'vulnerability' or 'vulnerabilities'"
    );
  } catch (error) {
    return handleRouteError(error);
  }
}
