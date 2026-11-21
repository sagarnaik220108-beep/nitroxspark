import type {
  Severity,
  SupportedLanguage,
  VulnerabilityCategory,
} from "./security.types";

/**
 * Vulnerability payload accepted by the Secure Fix Engine.
 * Compatible with DetectedVulnerability outputs as well as lightweight payloads.
 */
export interface FixVulnerabilityInput {
  ruleId: string;
  name?: string;
  title?: string;
  category: VulnerabilityCategory | string;
  severity: Severity;
  fileLine?: number;
  line?: number;
  location?: {
    line: number;
    endLine?: number;
  };
  matchedText?: string;
  language?: SupportedLanguage;
  cweId?: string;
  description?: string;
}

/**
 * Input to generate a secure code fix for a single vulnerability.
 */
export interface SecureFixInput {
  originalCode: string;
  vulnerability: FixVulnerabilityInput;
}

/**
 * Describes a single line-level modification produced by a fixer.
 */
export interface LineChange {
  lineNumber: number;
  originalLine: string;
  updatedLine: string;
  reason: string;
}

/**
 * Quantifies the security risk reduction achieved by applying a fix.
 */
export interface RiskReduction {
  beforeScore: number;
  afterScore: number;
  reductionPoints: number;
  reductionPercent: number;
  severityBefore: Severity;
  severityAfter: Severity | "resolved";
  rationale: string;
}

/**
 * Structured output returned by a single vulnerability fix operation.
 */
export interface SecureFixResult {
  originalCode: string;
  secureCode: string;
  linesChanged: LineChange[];
  changedLineNumbers: number[];
  summary: string;
  riskReduction: RiskReduction;
  fixerId: string;
  applied: boolean;
  notes?: string[];
}

/**
 * Summary entry for an individual fix within a batch fix run.
 */
export interface AppliedFixSummary {
  ruleId: string;
  fixerId: string;
  applied: boolean;
  summary: string;
  changedLineNumbers: number[];
}

/**
 * Structured output returned when fixing multiple vulnerabilities in one pass.
 */
export interface BatchSecureFixResult {
  originalCode: string;
  secureCode: string;
  linesChanged: LineChange[];
  changedLineNumbers: number[];
  summary: string;
  riskReduction: RiskReduction;
  appliedFixes: AppliedFixSummary[];
}

/**
 * Public metadata describing a registered fixer module.
 */
export interface FixerMetadata {
  id: string;
  name: string;
  description: string;
  supportedRuleIds: readonly string[];
  supportedCategories: readonly string[];
}

/**
 * Pluggable contract for all Secure Fix Engine fixers.
 * Register new fixers via `FixerRegistry.register(fixer)`.
 */
export interface VulnerabilityFixer {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly supportedRuleIds: readonly string[];
  readonly supportedCategories: readonly string[];
  canHandle(vulnerability: FixVulnerabilityInput): boolean;
  apply(input: SecureFixInput): SecureFixResult;
}
