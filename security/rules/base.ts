import type {
  CustomRuleRow,
  RemediationSuggestion,
  RuleContext,
  RuleMatch,
  SecurityRule,
  Severity,
  SupportedLanguage,
  VulnerabilityCategory,
} from "@/types";
import {
  extractCodeSnippet,
  offsetToLineColumn,
  redactSecretValue,
} from "@/utils";

export interface RegexRuleConfig {
  id: string;
  name: string;
  description: string;
  explanation: string;
  severity: Severity;
  category: VulnerabilityCategory;
  cweId: string;
  owaspCategory: string;
  languages: readonly SupportedLanguage[] | "*";
  tags: readonly string[];
  patterns: readonly RegExp[];
  confidence?: number;
  redactMatch?: boolean;
  enabledByDefault?: boolean;
  /**
   * Optional predicate to filter out false positives on a candidate match.
   */
  filterMatch?: (match: RegExpExecArray, context: RuleContext) => boolean;
  remediation: RemediationSuggestion;
}

/**
 * Factory helper for declarative regex-based security rules.
 * Guarantees stateless global matching, accurate line/column mapping,
 * optional secret redaction, and safe infinite-loop protection.
 */
export function createRegexRule(config: RegexRuleConfig): SecurityRule {
  return {
    id: config.id,
    name: config.name,
    description: config.description,
    explanation: config.explanation,
    severity: config.severity,
    category: config.category,
    cweId: config.cweId,
    owaspCategory: config.owaspCategory,
    languages: config.languages,
    tags: config.tags,
    enabledByDefault: config.enabledByDefault ?? true,
    remediation: config.remediation,

    evaluate(context: RuleContext): RuleMatch[] {
      const matches: RuleMatch[] = [];
      const seenLineCols = new Set<string>();

      for (const sourcePattern of config.patterns) {
        const flags = sourcePattern.flags.includes("g")
          ? sourcePattern.flags
          : `${sourcePattern.flags}g`;
        const regex = new RegExp(sourcePattern.source, flags);

        let match: RegExpExecArray | null;
        while ((match = regex.exec(context.code)) !== null) {
          if (match[0].length === 0) {
            regex.lastIndex += 1;
            continue;
          }

          if (config.filterMatch && !config.filterMatch(match, context)) {
            continue;
          }

          const startPos = offsetToLineColumn(context.code, match.index);
          const endPos = offsetToLineColumn(
            context.code,
            match.index + match[0].length
          );
          const dedupeKey = `${startPos.line}:${startPos.column}`;

          if (seenLineCols.has(dedupeKey)) {
            continue;
          }
          seenLineCols.add(dedupeKey);

          const rawMatchedText = match[0].trim();
          const matchedText = config.redactMatch
            ? redactSecretValue(rawMatchedText)
            : rawMatchedText.slice(0, 240);

          let snippet = extractCodeSnippet(context.lines, startPos.line);
          if (config.redactMatch && rawMatchedText.length > 0) {
            snippet = snippet.replaceAll(rawMatchedText, matchedText);
          }

          matches.push({
            line: startPos.line,
            column: startPos.column,
            endLine: endPos.line,
            endColumn: endPos.column,
            matchedText,
            snippet,
            confidence: config.confidence ?? 0.85,
          });
        }
      }

      return matches;
    },
  };
}

/**
 * Compiles a user-defined custom rule stored in Supabase into an executable SecurityRule.
 */
export function compileCustomRule(row: CustomRuleRow): SecurityRule {
  const safeFlags = row.pattern_flags.includes("g")
    ? row.pattern_flags
    : `${row.pattern_flags}g`;

  return createRegexRule({
    id: row.rule_key,
    name: row.name,
    description: row.description,
    explanation: row.explanation,
    severity: row.severity,
    category: row.category,
    cweId: row.cwe_id,
    owaspCategory: row.owasp_category,
    languages: row.languages,
    tags: ["custom", row.category],
    patterns: [new RegExp(row.pattern, safeFlags)],
    confidence: 0.8,
    enabledByDefault: row.enabled,
    remediation: row.remediation,
  });
}
