import type {
  DetectedVulnerability,
  EngineAnalysisResult,
  RuleContext,
  SecurityRule,
  SupportedLanguage,
} from "@/types";
import {
  buildScanSummary,
  buildSeverityBreakdown,
  calculateRiskGrade,
  calculateRiskScore,
  compareSeverity,
  detectLanguage,
  hashSourceCode,
} from "@/utils";
import { defaultRuleRegistry, RuleRegistry } from "./registry";
import { buildContextualRemediation } from "./remediation/fix-generator";

export interface AnalyzeCodeOptions {
  code: string;
  fileName?: string;
  language?: SupportedLanguage;
  enabledRuleIds?: string[];
  disabledRuleIds?: string[];
  extraRules?: SecurityRule[];
}

/**
 * Sentinel AI Core Security Engine.
 * Orchestrates language detection, rule resolution, isolated rule execution,
 * contextual remediation synthesis, and risk scoring.
 */
export class SecurityEngine {
  constructor(private readonly registry: RuleRegistry = defaultRuleRegistry) {}

  public analyze(options: AnalyzeCodeOptions): EngineAnalysisResult {
    const startedAt = performance.now();
    const language =
      options.language && options.language !== "unknown"
        ? options.language
        : detectLanguage(options.code, options.fileName);

    const lines = options.code.split(/\r?\n/);
    const context: RuleContext = {
      code: options.code,
      lines,
      language,
      fileName: options.fileName,
    };

    const activeRules = this.registry.resolveForScan({
      language,
      enabledRuleIds: options.enabledRuleIds,
      disabledRuleIds: options.disabledRuleIds,
      extraRules: options.extraRules,
    });

    const vulnerabilities: DetectedVulnerability[] = [];

    for (const rule of activeRules) {
      try {
        const matches = rule.evaluate(context);
        for (const match of matches) {
          vulnerabilities.push({
            ruleId: rule.id,
            title: rule.name,
            description: rule.description,
            explanation: match.customExplanation ?? rule.explanation,
            severity: rule.severity,
            category: rule.category,
            cweId: rule.cweId,
            owaspCategory: rule.owaspCategory,
            confidence: match.confidence ?? 0.85,
            location: {
              line: match.line,
              column: match.column,
              endLine: match.endLine,
              endColumn: match.endColumn,
              snippet: match.snippet,
            },
            matchedText: match.matchedText,
            remediation: buildContextualRemediation(rule, match),
          });
        }
      } catch (ruleError) {
        // Isolate individual rule failures so one misbehaving custom rule never crashes a scan.
        console.error(
          `[Sentinel AI] Rule '${rule.id}' threw during evaluation:`,
          ruleError
        );
      }
    }

    vulnerabilities.sort((a, b) => {
      const severityCmp = compareSeverity(a.severity, b.severity);
      if (severityCmp !== 0) return severityCmp;
      return a.location.line - b.location.line;
    });

    const severityBreakdown = buildSeverityBreakdown(vulnerabilities);
    const riskScore = calculateRiskScore(vulnerabilities);
    const riskGrade = calculateRiskGrade(riskScore);
    const summary = buildScanSummary(severityBreakdown, riskScore, riskGrade);
    const durationMs = Math.max(1, Math.round(performance.now() - startedAt));

    return {
      language,
      codeHash: hashSourceCode(options.code),
      lineCount: lines.length,
      riskScore,
      riskGrade,
      summary,
      severityBreakdown,
      vulnerabilities,
      executedRulesCount: activeRules.length,
      durationMs,
    };
  }
}

export const defaultSecurityEngine = new SecurityEngine(defaultRuleRegistry);
