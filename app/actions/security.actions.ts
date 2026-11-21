"use server";

import { z } from "zod";
import {
  analyzeCode,
  type StructuredSecurityReport,
} from "@/security/analyzer";
import {
  explanationService,
  fixService,
  reportGeneratorService,
  scanService,
  scoreService,
  simulationEngineService,
} from "@/services";
import type { ReportGenerationResult } from "@/services/report-generator.service";
import type { ScanWithVulnerabilities } from "@/services/scan.service";
import type { ActionResult } from "@/types";
import type {
  BeginnerFriendlyExplanation,
  ExplanationOptions,
  VulnerabilityExplanationInput,
} from "@/types/explanation.types";
import type { BatchSecureFixResult, SecureFixResult } from "@/types/fix.types";
import type { SecurityScoreReport } from "@/types/score.types";
import type { SimulationRunResponse } from "@/types/simulation.types";
import {
  handleActionError,
  parseOrThrow,
  supportedLanguageSchema,
} from "@/utils";

const MAX_CODE_BYTES = Number(process.env.MAX_CODE_SIZE_BYTES ?? 262_144);

const analyzeSnippetActionSchema = z.object({
  code: z
    .string()
    .min(1, "Source code cannot be empty")
    .refine(
      (val) => new TextEncoder().encode(val).length <= MAX_CODE_BYTES,
      `Source code exceeds maximum allowed size (${MAX_CODE_BYTES} bytes)`
    ),
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

export type AnalyzeCodeSnippetInput = z.infer<typeof analyzeSnippetActionSchema>;

/**
 * Runs an authenticated, persisted code scan via `scanService` and returns
 * the created scan record together with all persisted vulnerabilities.
 */
export async function runCodeScanAction(
  input: unknown
): Promise<ActionResult<ScanWithVulnerabilities>> {
  try {
    const data = await scanService.createAndRunScan(input);
    return { success: true, data };
  } catch (error) {
    return handleActionError(error);
  }
}

/**
 * Performs a stateless security analysis on a source code snippet without
 * requiring persistence, returning a structured vulnerability report.
 */
export async function analyzeCodeSnippetAction(
  input: unknown
): Promise<ActionResult<StructuredSecurityReport>> {
  try {
    const parsed = parseOrThrow(analyzeSnippetActionSchema, input);
    const report = analyzeCode(parsed.code, {
      fileName: parsed.fileName,
      language: parsed.language,
      enabledRuleIds: parsed.enabledRuleIds,
      disabledRuleIds: parsed.disabledRuleIds,
    });
    return { success: true, data: report };
  } catch (error) {
    return handleActionError(error);
  }
}

/**
 * Generates a beginner-friendly structured explanation for a detected vulnerability,
 * optionally enhanced by the configured LLM provider.
 */
export async function explainVulnerabilityAction(
  input: VulnerabilityExplanationInput,
  options?: ExplanationOptions
): Promise<ActionResult<BeginnerFriendlyExplanation>> {
  try {
    const data = await explanationService.explain(input, options);
    return { success: true, data };
  } catch (error) {
    return handleActionError(error);
  }
}

/**
 * Generates a deterministic secure code patch for a single vulnerability or
 * batch of vulnerabilities via `fixService`.
 */
export async function generateSecureFixAction(
  input: unknown
): Promise<ActionResult<SecureFixResult | BatchSecureFixResult>> {
  try {
    const data = fixService.processFixRequest(input);
    return { success: true, data };
  } catch (error) {
    return handleActionError(error);
  }
}

/**
 * Runs one, many, or all synthetic Before-vs-After attack simulations via
 * `simulationEngineService`.
 */
export async function runAttackSimulationAction(
  input?: unknown
): Promise<ActionResult<SimulationRunResponse>> {
  try {
    const data = simulationEngineService.executeSimulationRequest(input);
    return { success: true, data };
  } catch (error) {
    return handleActionError(error);
  }
}

/**
 * Calculates a security posture score.
 * - When `input` is provided, evaluates the supplied metrics payload directly.
 * - When `input` is omitted, aggregates live metrics for the authenticated user.
 */
export async function calculateSecurityScoreAction(
  input?: unknown
): Promise<ActionResult<SecurityScoreReport>> {
  try {
    const data =
      input !== undefined
        ? scoreService.calculateFromInput(input)
        : await scoreService.calculateForAuthenticatedUser();
    return { success: true, data };
  } catch (error) {
    return handleActionError(error);
  }
}

/**
 * Generates a structured security report bundle (JSON, HTML, and/or PDF-ready)
 * via `reportGeneratorService`.
 */
export async function generateSecurityReportAction(
  input: unknown
): Promise<ActionResult<ReportGenerationResult>> {
  try {
    const data = reportGeneratorService.generateFromRequest(input);
    return { success: true, data };
  } catch (error) {
    return handleActionError(error);
  }
}
