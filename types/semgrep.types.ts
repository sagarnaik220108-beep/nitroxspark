import type {
  StructuredSecurityReport,
  StructuredVulnerability,
} from "@/security/analyzer";
import type { SupportedLanguage } from "./security.types";

export type SemgrepEngineMode = "cli" | "builtin-rules";

export type SemgrepRuleset =
  | "auto"
  | "p/security-audit"
  | "p/owasp-top-ten"
  | "p/javascript"
  | "p/typescript"
  | "p/python"
  | "p/secrets";

export interface SemgrepCliPosition {
  line: number;
  col: number;
  offset?: number;
}

export interface SemgrepCliMetadata {
  cwe?: string | string[];
  owasp?: string | string[];
  category?: string;
  confidence?: string;
  impact?: string;
  likelihood?: string;
  references?: string[];
  technology?: string[];
  vulnerability_class?: string[];
  source?: string;
  shortlink?: string;
}

export interface SemgrepCliExtra {
  message: string;
  severity: string;
  lines?: string;
  fix?: string;
  metadata?: SemgrepCliMetadata;
  fingerprint?: string;
  engine_kind?: string;
  validation_state?: string;
}

export interface SemgrepCliResult {
  check_id: string;
  path: string;
  start: SemgrepCliPosition;
  end: SemgrepCliPosition;
  extra: SemgrepCliExtra;
}

export interface SemgrepCliError {
  code?: number;
  level?: string;
  type?: string | unknown[];
  message?: string;
  long_msg?: string;
  short_msg?: string;
}

export interface SemgrepCliOutput {
  version?: string;
  results: SemgrepCliResult[];
  errors?: SemgrepCliError[];
  paths?: {
    scanned?: string[];
    skipped?: unknown[];
  };
}

export interface SemgrepScanOptions {
  code: string;
  fileName?: string;
  language?: SupportedLanguage;
  ruleset?: SemgrepRuleset;
  preferCli?: boolean;
}

export interface SemgrepScanResult {
  engine: "semgrep";
  engineMode: SemgrepEngineMode;
  cliAvailable: boolean;
  cliVersion: string | null;
  ruleset: SemgrepRuleset;
  language: SupportedLanguage;
  findings: StructuredVulnerability[];
  rawMatchCount: number;
  executedRulesCount: number;
  durationMs: number;
  fallbackReason?: string;
}

export interface SemgrepStatusResponse {
  cliAvailable: boolean;
  cliVersion: string | null;
  activeMode: SemgrepEngineMode;
  supportedRulesets: readonly SemgrepRuleset[];
  builtinRulesCount: number;
}

export interface SemgrepEngineBreakdown {
  sentinelFindingsCount: number;
  semgrepFindingsCount: number;
  deduplicatedCount: number;
  mergedTotalCount: number;
  enginesUsed: readonly string[];
  semgrepMode: SemgrepEngineMode;
}

export interface SemgrepCombinedReport extends StructuredSecurityReport {
  engineBreakdown: SemgrepEngineBreakdown;
}

export interface SemgrepServiceScanResponse {
  semgrep: SemgrepScanResult;
  combinedReport: SemgrepCombinedReport;
}
