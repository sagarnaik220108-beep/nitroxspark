/**
 * Core domain types for the Sentinel AI Security Engine.
 * Designed so new languages, categories, and rules can be added without breaking callers.
 */

export type SupportedLanguage =
  | "typescript"
  | "javascript"
  | "python"
  | "sql"
  | "java"
  | "go"
  | "php"
  | "ruby"
  | "csharp"
  | "unknown";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type VulnerabilityCategory =
  | "injection"
  | "xss"
  | "secrets"
  | "authentication"
  | "authorization"
  | "ssrf"
  | "path-traversal"
  | "cryptography"
  | "misconfiguration"
  | "deserialization"
  | "other";

export type ScanStatus = "pending" | "processing" | "completed" | "failed";

export type VulnerabilityStatus =
  | "open"
  | "acknowledged"
  | "fixed"
  | "false_positive";

export interface CodeLocation {
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  snippet: string;
}

export interface RemediationSuggestion {
  summary: string;
  explanation: string;
  secureCodeExample: string;
  patchDiff?: string;
  references: string[];
}

export interface DetectedVulnerability {
  ruleId: string;
  title: string;
  description: string;
  explanation: string;
  severity: Severity;
  category: VulnerabilityCategory;
  cweId: string;
  owaspCategory: string;
  confidence: number; // 0.0 to 1.0
  location: CodeLocation;
  matchedText: string;
  remediation: RemediationSuggestion;
}

export interface RuleContext {
  code: string;
  lines: string[];
  language: SupportedLanguage;
  fileName?: string;
}

export interface RuleMatch {
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  matchedText: string;
  snippet: string;
  confidence?: number;
  customExplanation?: string;
  customFixExample?: string;
}

/**
 * Pluggable Security Rule contract.
 * Implement this interface and register the rule in `security/rules/index.ts`
 * (or dynamically via `RuleRegistry.register`) to extend Sentinel AI.
 */
export interface SecurityRule {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly explanation: string;
  readonly severity: Severity;
  readonly category: VulnerabilityCategory;
  readonly cweId: string;
  readonly owaspCategory: string;
  readonly languages: readonly SupportedLanguage[] | "*";
  readonly tags: readonly string[];
  readonly enabledByDefault: boolean;
  readonly remediation: RemediationSuggestion;
  evaluate(context: RuleContext): RuleMatch[];
}

export interface RuleMetadata {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: VulnerabilityCategory;
  cweId: string;
  owaspCategory: string;
  languages: readonly SupportedLanguage[] | "*";
  tags: readonly string[];
  enabled: boolean;
  source: "builtin" | "custom";
}

export interface SeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface EngineAnalysisResult {
  language: SupportedLanguage;
  codeHash: string;
  lineCount: number;
  riskScore: number; // 0 (safe) to 100 (critical risk)
  riskGrade: "A" | "B" | "C" | "D" | "F";
  summary: string;
  severityBreakdown: SeverityBreakdown;
  vulnerabilities: DetectedVulnerability[];
  executedRulesCount: number;
  durationMs: number;
}

export interface AttackStep {
  stepNumber: number;
  phase:
    | "reconnaissance"
    | "weaponization"
    | "delivery"
    | "exploitation"
    | "impact";
  title: string;
  description: string;
  technicalDetail: string;
}

export interface AttackSimulationResult {
  vulnerabilityId?: string;
  ruleId: string;
  attackName: string;
  mitreAttackTechnique: string;
  severity: Severity;
  likelihood: "low" | "medium" | "high";
  /**
   * Safe, sanitized proof-of-concept payload for educational & defensive testing only.
   */
  simulatedPayload: string;
  entryPoint: string;
  killChain: AttackStep[];
  potentialImpact: string[];
  blastRadius: "isolated" | "service" | "data-tier" | "organization";
  detectionSignatures: string[];
  defensiveControls: string[];
  disclaimer: string;
}
