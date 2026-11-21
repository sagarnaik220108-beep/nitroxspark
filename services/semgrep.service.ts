import { z } from "zod";
import { analyzeCode } from "@/security/analyzer";
import {
  defaultSemgrepEngine,
  SemgrepEngine,
} from "@/security/semgrep/semgrep-engine";
import {
  SEMGREP_BUILTIN_RULES,
  SEMGREP_SUPPORTED_RULESETS,
} from "@/security/semgrep/semgrep-rules";
import type {
  SemgrepCombinedReport,
  SemgrepEngineMode,
  SemgrepServiceScanResponse,
  SemgrepStatusResponse,
} from "@/types/semgrep.types";
import {
  buildScanSummary,
  buildSeverityBreakdown,
  calculateRiskGrade,
  calculateRiskScore,
  hashSourceCode,
  parseOrThrow,
  supportedLanguageSchema,
} from "@/utils";

export const semgrepRulesetSchema = z.enum([
  "auto",
  "p/security-audit",
  "p/owasp-top-ten",
  "p/javascript",
  "p/typescript",
  "p/python",
  "p/secrets",
]);

export const semgrepScanRequestSchema = z.object({
  code: z.string().min(1, "Source code cannot be empty"),
  fileName: z
    .string()
    .trim()
    .min(1, "File name cannot be empty")
    .max(255, "File name must be 255 characters or fewer")
    .optional(),
  language: supportedLanguageSchema.optional(),
  ruleset: semgrepRulesetSchema.default("auto"),
  preferCli: z.boolean().optional(),
  combineWithSentinel: z.boolean().default(true),
});

export type SemgrepScanRequestInput = z.infer<typeof semgrepScanRequestSchema>;

/**
 * Application service orchestrating Semgrep engine status checks,
 * standalone Semgrep scans, and combined Sentinel AI + Semgrep analysis.
 */
export class SemgrepService {
  constructor(private readonly engine: SemgrepEngine = defaultSemgrepEngine) {}

  public async getStatus(): Promise<SemgrepStatusResponse> {
    const cliStatus = await this.engine.checkCliAvailability();
    const activeMode: SemgrepEngineMode =
      cliStatus.cliAvailable && process.env.SEMGREP_MODE !== "builtin"
        ? "cli"
        : "builtin-rules";

    return {
      cliAvailable: cliStatus.cliAvailable,
      cliVersion: cliStatus.cliVersion,
      activeMode,
      supportedRulesets: SEMGREP_SUPPORTED_RULESETS,
      builtinRulesCount: SEMGREP_BUILTIN_RULES.length,
    };
  }

  public async scanCode(rawInput: unknown): Promise<SemgrepServiceScanResponse> {
    const input = parseOrThrow(semgrepScanRequestSchema, rawInput);

    const semgrepResult = await this.engine.scan({
      code: input.code,
      fileName: input.fileName,
      language: input.language,
      ruleset: input.ruleset,
      preferCli: input.preferCli,
    });

    if (input.combineWithSentinel) {
      const sentinelReport = analyzeCode(input.code, {
        fileName: input.fileName,
        language: input.language ?? semgrepResult.language,
      });

      const mergedVulnerabilities = this.engine.mergeFindings(
        sentinelReport.vulnerabilities,
        semgrepResult.findings
      );

      const severityBreakdown = buildSeverityBreakdown(mergedVulnerabilities);
      const riskScore = calculateRiskScore(
        mergedVulnerabilities.map((vuln) => ({
          severity: vuln.severity,
          confidence: vuln.confidenceScore,
        }))
      );
      const riskGrade = calculateRiskGrade(riskScore);
      const summary = buildScanSummary(severityBreakdown, riskScore, riskGrade);

      const totalRaw =
        sentinelReport.vulnerabilities.length + semgrepResult.findings.length;
      const deduplicatedCount = Math.max(
        0,
        totalRaw - mergedVulnerabilities.length
      );

      const combinedReport: SemgrepCombinedReport = {
        ...(input.fileName ? { fileName: input.fileName } : {}),
        language: sentinelReport.language,
        codeHash: sentinelReport.codeHash,
        lineCount: sentinelReport.lineCount,
        vulnerabilities: mergedVulnerabilities,
        severityBreakdown,
        riskScore,
        riskGrade,
        summary,
        executedRulesCount:
          sentinelReport.executedRulesCount + semgrepResult.executedRulesCount,
        durationMs: sentinelReport.durationMs + semgrepResult.durationMs,
        generatedAt: new Date().toISOString(),
        engineBreakdown: {
          sentinelFindingsCount: sentinelReport.vulnerabilities.length,
          semgrepFindingsCount: semgrepResult.findings.length,
          deduplicatedCount,
          mergedTotalCount: mergedVulnerabilities.length,
          enginesUsed: ["sentinel-ai", "semgrep"],
          semgrepMode: semgrepResult.engineMode,
        },
      };

      return {
        semgrep: semgrepResult,
        combinedReport,
      };
    }

    const severityBreakdown = buildSeverityBreakdown(semgrepResult.findings);
    const riskScore = calculateRiskScore(
      semgrepResult.findings.map((vuln) => ({
        severity: vuln.severity,
        confidence: vuln.confidenceScore,
      }))
    );
    const riskGrade = calculateRiskGrade(riskScore);
    const summary = buildScanSummary(severityBreakdown, riskScore, riskGrade);
    const lineCount = input.code.split(/\r?\n/).length;

    const combinedReport: SemgrepCombinedReport = {
      ...(input.fileName ? { fileName: input.fileName } : {}),
      language: semgrepResult.language,
      codeHash: hashSourceCode(input.code),
      lineCount,
      vulnerabilities: semgrepResult.findings,
      severityBreakdown,
      riskScore,
      riskGrade,
      summary,
      executedRulesCount: semgrepResult.executedRulesCount,
      durationMs: semgrepResult.durationMs,
      generatedAt: new Date().toISOString(),
      engineBreakdown: {
        sentinelFindingsCount: 0,
        semgrepFindingsCount: semgrepResult.findings.length,
        deduplicatedCount: 0,
        mergedTotalCount: semgrepResult.findings.length,
        enginesUsed: ["semgrep"],
        semgrepMode: semgrepResult.engineMode,
      },
    };

    return {
      semgrep: semgrepResult,
      combinedReport,
    };
  }
}

export const semgrepService = new SemgrepService();
