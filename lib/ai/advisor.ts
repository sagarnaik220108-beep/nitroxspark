import type { DetectedVulnerability, SupportedLanguage } from "@/types";

export interface SecurityAdvisorEnrichment {
  enhancedExplanation: string;
  contextualFixNotes: string;
}

/**
 * Pluggable AI advisor abstraction.
 * By default, Sentinel AI operates deterministically using its built-in Security Engine
 * (zero external API latency or cost). To enable LLM-powered deep explanations,
 * implement a provider adapter here when `AI_PROVIDER` and `AI_API_KEY` are configured.
 */
export async function enrichVulnerabilityWithAI(
  vulnerability: DetectedVulnerability,
  language: SupportedLanguage
): Promise<SecurityAdvisorEnrichment> {
  return {
    enhancedExplanation: `${vulnerability.explanation} (Language context: ${language}, mapped to ${vulnerability.cweId} / ${vulnerability.owaspCategory}).`,
    contextualFixNotes: vulnerability.remediation.explanation,
  };
}
