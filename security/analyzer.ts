import type {
  DetectedVulnerability,
  SecurityRule,
  Severity,
  SeverityBreakdown,
  SupportedLanguage,
  VulnerabilityCategory,
} from "@/types";
import { SecurityEngine } from "./engine";
import { defaultRuleRegistry, RuleRegistry } from "./registry";

export interface StructuredVulnerability {
  ruleId: string;
  name: string;
  severity: Severity;
  category: VulnerabilityCategory;
  cweId: string;
  owaspCategory: string;
  description: string;
  risk: string;
  fileLine: number;
  column: number;
  snippet: string;
  suggestedFix: string;
  secureCodeExample: string;
  confidenceScore: number;
}

export interface StructuredSecurityReport {
  fileName?: string;
  language: SupportedLanguage;
  codeHash: string;
  lineCount: number;
  vulnerabilities: StructuredVulnerability[];
  severityBreakdown: SeverityBreakdown;
  riskScore: number;
  riskGrade: "A" | "B" | "C" | "D" | "F";
  summary: string;
  executedRulesCount: number;
  durationMs: number;
  generatedAt: string;
}

export interface SecurityAnalysisOptions {
  fileName?: string;
  language?: SupportedLanguage;
  enabledRuleIds?: string[];
  disabledRuleIds?: string[];
  extraRules?: SecurityRule[];
}

function toStructuredVulnerability(
  vuln: DetectedVulnerability
): StructuredVulnerability {
  const clampedConfidence = Math.max(0, Math.min(1, vuln.confidence));
  return {
    ruleId: vuln.ruleId,
    name: vuln.title,
    severity: vuln.severity,
    category: vuln.category,
    cweId: vuln.cweId,
    owaspCategory: vuln.owaspCategory,
    description: vuln.description,
    risk: vuln.explanation,
    fileLine: vuln.location.line,
    column: vuln.location.column,
    snippet: vuln.location.snippet,
    suggestedFix: vuln.remediation.summary,
    secureCodeExample: vuln.remediation.secureCodeExample,
    confidenceScore: Math.round(clampedConfidence * 100) / 100,
  };
}

/**
 * Modular Security Analysis Engine for Sentinel AI.
 * Executes all registered rules from `RuleRegistry` against input source code
 * and produces one normalized, structured JSON security report.
 */
export class SecurityAnalysisEngine {
  private readonly engine: SecurityEngine;

  constructor(private readonly registry: RuleRegistry = defaultRuleRegistry) {
    this.engine = new SecurityEngine(this.registry);
  }

  public analyze(
    code: string,
    options: SecurityAnalysisOptions = {}
  ): StructuredSecurityReport {
    const result = this.engine.analyze({
      code,
      fileName: options.fileName,
      language: options.language,
      enabledRuleIds: options.enabledRuleIds,
      disabledRuleIds: options.disabledRuleIds,
      extraRules: options.extraRules,
    });

    return {
      ...(options.fileName ? { fileName: options.fileName } : {}),
      language: result.language,
      codeHash: result.codeHash,
      lineCount: result.lineCount,
      vulnerabilities: result.vulnerabilities.map(toStructuredVulnerability),
      severityBreakdown: result.severityBreakdown,
      riskScore: result.riskScore,
      riskGrade: result.riskGrade,
      summary: result.summary,
      executedRulesCount: result.executedRulesCount,
      durationMs: result.durationMs,
      generatedAt: new Date().toISOString(),
    };
  }
}

export const defaultSecurityAnalysisEngine = new SecurityAnalysisEngine(
  defaultRuleRegistry
);

/**
 * Convenience entry point to analyze source code with the default Sentinel AI rule registry
 * and return a single structured security report.
 */
export function analyzeCode(
  code: string,
  options: SecurityAnalysisOptions = {}
): StructuredSecurityReport {
  return defaultSecurityAnalysisEngine.analyze(code, options);
}
