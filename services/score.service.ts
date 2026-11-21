import { z } from "zod";
import {
  defaultSecurityScoreEngine,
  SecurityScoreEngine,
} from "@/security/scoring/score-engine";
import { authService } from "@/services/auth.service";
import type {
  RiskLevel,
  SecurityScoreInput,
  SecurityScoreReport,
} from "@/types/score.types";
import { InternalServerError } from "@/utils/errors";

const riskLevelSchema: z.ZodType<RiskLevel> = z.enum([
  "minimal",
  "low",
  "moderate",
  "high",
  "critical",
]);

const timeSavedInputSchema = z
  .object({
    minutes: z.number().finite().min(0),
    hours: z.number().finite().min(0).optional(),
    formatted: z.string().trim().min(1).max(64).optional(),
  })
  .strict();

/**
 * Zod schema validating incoming metrics payloads for `POST /api/score`
 * and `scoreService.calculateFromInput`.
 */
export const securityScoreInputSchema = z
  .object({
    overallSecurityScore: z.number().finite().min(0).max(100).optional(),
    riskLevel: riskLevelSchema.optional(),
    criticalIssues: z.number().int().min(0).default(0),
    highIssues: z.number().int().min(0).default(0),
    mediumIssues: z.number().int().min(0).default(0),
    lowIssues: z.number().int().min(0).default(0),
    filesScanned: z.number().int().min(0).default(0),
    threatsFixed: z.number().int().min(0).default(0),
    timeSaved: timeSavedInputSchema.optional(),
  })
  .strict();

export type ValidatedSecurityScoreInput = z.infer<
  typeof securityScoreInputSchema
>;

/**
 * Application service orchestrating Sentinel AI security score calculation
 * for both direct metric payloads and live authenticated Supabase telemetry.
 */
export class ScoreService {
  private readonly engine: SecurityScoreEngine;

  constructor(engine: SecurityScoreEngine = defaultSecurityScoreEngine) {
    this.engine = engine;
  }

  /**
   * Validates an untrusted metrics payload with Zod and computes a
   * `SecurityScoreReport`.
   */
  public calculateFromInput(rawInput: unknown): SecurityScoreReport {
    const parsed = securityScoreInputSchema.parse(rawInput);
    const input: SecurityScoreInput = {
      criticalIssues: parsed.criticalIssues,
      highIssues: parsed.highIssues,
      mediumIssues: parsed.mediumIssues,
      lowIssues: parsed.lowIssues,
      filesScanned: parsed.filesScanned,
      threatsFixed: parsed.threatsFixed,
      ...(parsed.overallSecurityScore !== undefined
        ? { overallSecurityScore: parsed.overallSecurityScore }
        : {}),
      ...(parsed.riskLevel !== undefined
        ? { riskLevel: parsed.riskLevel }
        : {}),
      ...(parsed.timeSaved !== undefined
        ? { timeSaved: parsed.timeSaved }
        : {}),
    };

    return this.engine.calculate(input);
  }

  /**
   * Queries the authenticated user's `scans` and `vulnerabilities` tables in
   * Supabase, aggregates active issue counts, scanned file counts, and fixed
   * threats, and returns the live `SecurityScoreReport`.
   */
  public async calculateForAuthenticatedUser(): Promise<SecurityScoreReport> {
    const { user, supabase } = await authService.requireAuthenticatedUser();

    const [scansResult, vulnerabilitiesResult] = await Promise.all([
      supabase
        .from("scans")
        .select("*", { count: "exact", head: true })
        .eq("user_id", user.id),
      supabase
        .from("vulnerabilities")
        .select("severity, status")
        .eq("user_id", user.id),
    ]);

    if (scansResult.error) {
      throw new InternalServerError(
        "Failed to aggregate user scan metrics",
        scansResult.error.message
      );
    }

    if (vulnerabilitiesResult.error) {
      throw new InternalServerError(
        "Failed to aggregate user vulnerability metrics",
        vulnerabilitiesResult.error.message
      );
    }

    let criticalIssues = 0;
    let highIssues = 0;
    let mediumIssues = 0;
    let lowIssues = 0;
    let threatsFixed = 0;

    const vulnerabilities = vulnerabilitiesResult.data ?? [];
    for (const vuln of vulnerabilities) {
      if (vuln.status === "fixed") {
        threatsFixed += 1;
        continue;
      }

      if (vuln.status === "false_positive") {
        continue;
      }

      switch (vuln.severity) {
        case "critical":
          criticalIssues += 1;
          break;
        case "high":
          highIssues += 1;
          break;
        case "medium":
          mediumIssues += 1;
          break;
        case "low":
          lowIssues += 1;
          break;
        case "info":
          // Informational findings do not penalize the posture score.
          break;
      }
    }

    const filesScanned = scansResult.count ?? 0;

    return this.engine.calculate({
      criticalIssues,
      highIssues,
      mediumIssues,
      lowIssues,
      filesScanned,
      threatsFixed,
    });
  }
}

export const scoreService = new ScoreService();
