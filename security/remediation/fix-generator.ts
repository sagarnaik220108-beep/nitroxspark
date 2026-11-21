import type {
  RemediationSuggestion,
  RuleMatch,
  SecurityRule,
} from "@/types";

/**
 * Produces a contextual RemediationSuggestion for a specific rule match,
 * attaching a unified diff hint referencing the exact vulnerable line.
 */
export function buildContextualRemediation(
  rule: SecurityRule,
  match: RuleMatch
): RemediationSuggestion {
  const vulnerableLine = match.matchedText.split("\n")[0]?.trim() ?? "";
  const recommendedFirstLine =
    (match.customFixExample ?? rule.remediation.secureCodeExample)
      .split("\n")
      .find((line) => line.trim().length > 0 && !line.trim().startsWith("//"))
      ?.trim() ?? "// Apply parameterized / validated alternative";

  const patchDiff = [
    `@@ -${match.line},1 +${match.line},1 @@`,
    `- ${vulnerableLine}`,
    `+ ${recommendedFirstLine}`,
  ].join("\n");

  return {
    summary: rule.remediation.summary,
    explanation: rule.remediation.explanation,
    secureCodeExample:
      match.customFixExample ?? rule.remediation.secureCodeExample,
    patchDiff,
    references: [...rule.remediation.references],
  };
}
