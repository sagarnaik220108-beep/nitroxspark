export {
  analyzeCode,
  defaultSecurityAnalysisEngine,
  SecurityAnalysisEngine,
} from "./analyzer";
export type {
  StructuredSecurityReport,
  StructuredVulnerability,
} from "./analyzer";
export { defaultSecurityEngine, SecurityEngine } from "./engine";
export type { AnalyzeCodeOptions } from "./engine";
export {
  CATEGORY_FALLBACK_TEMPLATES,
  CORE_EXPLANATION_TEMPLATES,
  GENERIC_FALLBACK_TEMPLATE,
} from "./explanations/templates";
export {
  BUILT_IN_FIXERS,
  defaultFixerRegistry,
  defaultSecureFixEngine,
  FixerRegistry,
  SecureFixEngine,
} from "./fixes";
export { defaultRuleRegistry, RuleRegistry } from "./registry";
export type { RuleFilterOptions } from "./registry";
export { buildContextualRemediation } from "./remediation/fix-generator";
export {
  defaultReportGenerator,
  SecurityReportGenerator,
} from "./reports/report-generator";
export {
  buildPdfReadyStructure,
  defaultReportTemplateRegistry,
  escapeHtml,
  htmlReportTemplate,
  jsonReportTemplate,
  pdfReadyReportTemplate,
  renderSecurityReportHtml,
  ReportTemplateRegistry,
} from "./reports/templates";
export { BUILT_IN_RULES, compileCustomRule, createRegexRule } from "./rules";
export {
  buildTimeSavedMetrics,
  calculateSecurityScore,
  defaultSecurityScoreEngine,
  formatTimeSaved,
  SecurityScoreEngine,
} from "./scoring/score-engine";
export {
  defaultSemgrepEngine,
  SemgrepEngine,
} from "./semgrep/semgrep-engine";
export {
  getApplicableBuiltinRules,
  runBuiltinSemgrepRules,
  SEMGREP_BUILTIN_RULES,
  SEMGREP_SUPPORTED_RULESETS,
} from "./semgrep/semgrep-rules";
export { simulateAttackForVulnerability } from "./simulator/attack-simulator";
export {
  AttackScenarioRegistry,
  BeforeAfterAttackSimulator,
  BUILTIN_ATTACK_SCENARIOS,
  defaultAttackScenarioRegistry,
  defaultBeforeAfterAttackSimulator,
} from "./simulator/scenarios";
