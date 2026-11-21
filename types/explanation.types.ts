import type {
  Severity,
  SupportedLanguage,
  VulnerabilityCategory,
} from "./security.types";

/**
 * Flexible input contract accepted by the Sentinel AI Explanation Service.
 * Supports both flat vulnerability payloads and normalized DetectedVulnerability fields.
 */
export interface VulnerabilityExplanationInput {
  ruleId?: string;
  /** Human-readable vulnerability name (alias for `title`). */
  name?: string;
  /** Human-readable vulnerability title (alias for `name`). */
  title?: string;
  severity?: Severity;
  category?: VulnerabilityCategory | string;
  description?: string;
  /** Vulnerable code excerpt (alias for `codeSnippet`). */
  snippet?: string;
  /** Vulnerable code excerpt (alias for `snippet`). */
  codeSnippet?: string;
  /** 1-based line number where the issue occurs (alias for `line`). */
  fileLine?: number;
  /** 1-based line number where the issue occurs (alias for `fileLine`). */
  line?: number;
  fileName?: string;
  language?: SupportedLanguage | string;
  cweId?: string;
  owaspCategory?: string;
}

/**
 * Optional runtime configuration for generating an explanation.
 */
export interface ExplanationOptions {
  /**
   * When true (default), allows optional LLM enhancement if `AI_PROVIDER` and
   * `AI_API_KEY` are configured. Set to false to force deterministic templates.
   */
  useAI?: boolean;
}

/**
 * Indicates whether the explanation came directly from curated templates
 * or was further tailored by a configured LLM provider.
 */
export type ExplanationSource = "template" | "ai-enhanced";

/**
 * Beginner-friendly structured JSON explanation returned by the Explanation Service.
 */
export interface BeginnerFriendlyExplanation {
  /** Clear, jargon-free explanation of what the vulnerability is. */
  whatItIs: string;
  /** Why developers (and AI code generators) commonly introduce this issue. */
  whyItHappens: string;
  /** Step-by-step beginner-friendly explanation of how attackers exploit it (defensive/educational). */
  howHackersExploitIt: string;
  /** Memorable everyday real-world analogy anyone can understand. */
  realWorldAnalogy: string;
  /** Concrete business and technical impact if exploited. */
  impact: string;
  /** Actionable secure engineering best practices to prevent the flaw. */
  bestPractice: string;
  /** Clean, well-commented secure code example showing the safe pattern. */
  secureVersion: string;

  /** Identifier of the explanation template used to build this response. */
  templateId: string;
  /** Resolved human-readable vulnerability name. */
  vulnerabilityName: string;
  /** Rule identifier if provided or resolved from the template. */
  ruleId?: string;
  /** Normalized severity level. */
  severity: Severity;
  /** Normalized vulnerability category. */
  category: string;
  /** Detected or provided source language. */
  language?: SupportedLanguage;
  /** 1-based line number where the vulnerability was detected. */
  fileLine?: number;
  /** Associated CWE identifier (e.g., CWE-89). */
  cweId?: string;
  /** Associated OWASP Top 10 category. */
  owaspCategory?: string;
  /** Whether this explanation used curated templates or optional AI enhancement. */
  source: ExplanationSource;
  /** Optional contextual note tying the explanation to the specific line/snippet/language. */
  contextNote?: string;
}

/**
 * Reusable explanation template stored in the Sentinel AI template registry.
 */
export interface ExplanationTemplate {
  /** Unique slug for the template (e.g., "sql-injection"). */
  readonly id: string;
  /** Friendly display title (e.g., "SQL Injection"). */
  readonly name: string;
  /** Sentinel rule IDs that map directly to this template (matched case-insensitively). */
  readonly ruleIds: readonly string[];
  /** Keywords matched against vulnerability name, title, description, or CWE ID. */
  readonly keywords: readonly string[];
  /** Primary security category this template belongs to. */
  readonly category: VulnerabilityCategory | string;
  /** Default severity used when the caller omits severity. */
  readonly defaultSeverity: Severity;
  /** Default CWE ID if not provided on the input. */
  readonly defaultCweId?: string;
  /** Default OWASP Top 10 mapping if not provided on the input. */
  readonly defaultOwaspCategory?: string;
  /** Whether this template is a fallback (category/generic) rather than a primary rule template. */
  readonly isFallback?: boolean;

  readonly whatItIs: string;
  readonly whyItHappens: string;
  readonly howHackersExploitIt: string;
  readonly realWorldAnalogy: string;
  readonly impact: string;
  readonly bestPractice: string;
  /** Default secure code example (TypeScript/JavaScript or general-purpose). */
  readonly secureVersion: string;
  /** Optional language-specific secure code examples (e.g., python, go, java). */
  readonly secureVersionsByLanguage?: Partial<Record<SupportedLanguage, string>>;
}

/**
 * Public metadata describing a supported explanation template.
 */
export interface ExplanationTemplateMetadata {
  id: string;
  name: string;
  category: string;
  defaultSeverity: Severity;
  ruleIds: readonly string[];
  keywords: readonly string[];
  defaultCweId?: string;
  defaultOwaspCategory?: string;
  supportedLanguages: readonly SupportedLanguage[];
}

/**
 * Aggregated result for batch vulnerability explanations.
 */
export interface BatchExplanationResult {
  total: number;
  explanations: BeginnerFriendlyExplanation[];
  severitySummary: Record<Severity, number>;
  sourceSummary: Record<ExplanationSource, number>;
}
