import type {
  FixVulnerabilityInput,
  LineChange,
  RiskReduction,
  SecureFixResult,
  VulnerabilityFixer,
} from "@/types/fix.types";
import type { Severity, SupportedLanguage } from "@/types/security.types";

export type { VulnerabilityFixer };

const SEVERITY_BASE_SCORE: Record<Severity, number> = {
  critical: 95,
  high: 80,
  medium: 55,
  low: 30,
  info: 15,
};

const SEVERITY_RESIDUAL_SCORE: Record<Severity, number> = {
  critical: 10,
  high: 8,
  medium: 5,
  low: 3,
  info: 0,
};

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/**
 * Computes line-by-line changes between `originalCode` and `secureCode` using an
 * LCS alignment so inserted lines (e.g. env guards or imports) do not cascade
 * false diffs onto unchanged trailing lines.
 */
export function computeLineChanges(
  originalCode: string,
  secureCode: string,
  reason: string
): { linesChanged: LineChange[]; changedLineNumbers: number[] } {
  if (originalCode === secureCode) {
    return { linesChanged: [], changedLineNumbers: [] };
  }

  const origLines = originalCode.split(/\r?\n/);
  const nextLines = secureCode.split(/\r?\n/);

  const m = origLines.length;
  const n = nextLines.length;

  // Build LCS table for line alignment (bounded for safety on very large files)
  if (m * n > 250_000) {
    return computeLinearLineChanges(origLines, nextLines, reason);
  }

  const dp: number[][] = Array.from({ length: m + 1 }, () =>
    new Array<number>(n + 1).fill(0)
  );

  for (let i = m - 1; i >= 0; i--) {
    const row = dp[i];
    const nextRow = dp[i + 1];
    if (!row || !nextRow) continue;

    for (let j = n - 1; j >= 0; j--) {
      if (origLines[i] === nextLines[j]) {
        row[j] = (nextRow[j + 1] ?? 0) + 1;
      } else {
        row[j] = Math.max(nextRow[j] ?? 0, row[j + 1] ?? 0);
      }
    }
  }

  const linesChanged: LineChange[] = [];
  let i = 0;
  let j = 0;

  while (i < m || j < n) {
    if (i < m && j < n && origLines[i] === nextLines[j]) {
      i++;
      j++;
      continue;
    }

    // Collect contiguous mismatch hunk so replacements pair up cleanly
    const origStart = i;
    const nextStart = j;

    while (i < m || j < n) {
      if (i < m && j < n && origLines[i] === nextLines[j]) {
        break;
      }
      const down = i < m ? (dp[i + 1]?.[j] ?? 0) : -1;
      const right = j < n ? (dp[i]?.[j + 1] ?? 0) : -1;
      if (i < m && (j >= n || down >= right)) {
        i++;
      } else if (j < n) {
        j++;
      }
    }

    const removed = origLines.slice(origStart, i);
    const added = nextLines.slice(nextStart, j);
    const pairedCount = Math.max(removed.length, added.length);

    for (let k = 0; k < pairedCount; k++) {
      const originalLine = removed[k] ?? "";
      const updatedLine = added[k] ?? "";
      if (originalLine === updatedLine) continue;

      const lineNumber = nextStart + k + 1;
      linesChanged.push({
        lineNumber,
        originalLine,
        updatedLine,
        reason,
      });
    }
  }

  const changedLineNumbers = Array.from(
    new Set(linesChanged.map((change) => change.lineNumber))
  ).sort((a, b) => a - b);

  return { linesChanged, changedLineNumbers };
}

function computeLinearLineChanges(
  origLines: string[],
  nextLines: string[],
  reason: string
): { linesChanged: LineChange[]; changedLineNumbers: number[] } {
  const maxLen = Math.max(origLines.length, nextLines.length);
  const linesChanged: LineChange[] = [];

  for (let i = 0; i < maxLen; i++) {
    const originalLine = origLines[i] ?? "";
    const updatedLine = nextLines[i] ?? "";
    if (originalLine !== updatedLine) {
      linesChanged.push({
        lineNumber: i + 1,
        originalLine,
        updatedLine,
        reason,
      });
    }
  }

  return {
    linesChanged,
    changedLineNumbers: linesChanged.map((c) => c.lineNumber),
  };
}

/**
 * Quantifies the risk reduction for a single vulnerability fix.
 */
export function calculateRiskReduction(
  severity: Severity,
  wasFixed: boolean,
  customRationale?: string
): RiskReduction {
  const beforeScore = SEVERITY_BASE_SCORE[severity];

  if (!wasFixed) {
    return {
      beforeScore,
      afterScore: beforeScore,
      reductionPoints: 0,
      reductionPercent: 0,
      severityBefore: severity,
      severityAfter: severity,
      rationale:
        customRationale ??
        `No automated code transformation was applied for this ${severity} vulnerability; manual remediation is required.`,
    };
  }

  const afterScore = SEVERITY_RESIDUAL_SCORE[severity];
  const reductionPoints = beforeScore - afterScore;
  const reductionPercent =
    beforeScore > 0 ? Math.round((reductionPoints / beforeScore) * 100) : 0;

  return {
    beforeScore,
    afterScore,
    reductionPoints,
    reductionPercent,
    severityBefore: severity,
    severityAfter: "resolved",
    rationale:
      customRationale ??
      `Resolved ${severity} vulnerability, lowering risk score from ${beforeScore} to ${afterScore} (-${reductionPoints} pts / -${reductionPercent}%).`,
  };
}

/**
 * Aggregates risk reduction across multiple vulnerabilities in a batch fix.
 */
export function calculateBatchRiskReduction(
  vulnerabilities: readonly FixVulnerabilityInput[],
  appliedFlags: readonly boolean[]
): RiskReduction {
  if (vulnerabilities.length === 0) {
    return {
      beforeScore: 0,
      afterScore: 0,
      reductionPoints: 0,
      reductionPercent: 0,
      severityBefore: "info",
      severityAfter: "resolved",
      rationale: "No vulnerabilities provided for remediation.",
    };
  }

  const severityWeights: Record<Severity, number> = {
    critical: 35,
    high: 25,
    medium: 15,
    low: 8,
    info: 3,
  };

  let rawBefore = 0;
  let rawAfter = 0;
  let highestBefore: Severity = "info";
  let highestRemaining: Severity | null = null;
  let fixedCount = 0;

  for (let idx = 0; idx < vulnerabilities.length; idx++) {
    const vuln = vulnerabilities[idx];
    if (!vuln) continue;
    const weight = severityWeights[vuln.severity];
    rawBefore += weight;

    if (SEVERITY_ORDER[vuln.severity] > SEVERITY_ORDER[highestBefore]) {
      highestBefore = vuln.severity;
    }

    if (appliedFlags[idx]) {
      fixedCount++;
      rawAfter += Math.round(weight * 0.1);
    } else {
      rawAfter += weight;
      if (
        !highestRemaining ||
        SEVERITY_ORDER[vuln.severity] > SEVERITY_ORDER[highestRemaining]
      ) {
        highestRemaining = vuln.severity;
      }
    }
  }

  const beforeScore = Math.min(100, rawBefore);
  const afterScore = Math.min(beforeScore, Math.min(100, rawAfter));
  const reductionPoints = Math.max(0, beforeScore - afterScore);
  const reductionPercent =
    beforeScore > 0 ? Math.round((reductionPoints / beforeScore) * 100) : 0;

  return {
    beforeScore,
    afterScore,
    reductionPoints,
    reductionPercent,
    severityBefore: highestBefore,
    severityAfter: highestRemaining ?? "resolved",
    rationale:
      fixedCount > 0
        ? `Remediated ${fixedCount} of ${vulnerabilities.length} vulnerabilities, reducing aggregate risk score from ${beforeScore} to ${afterScore} (-${reductionPercent}%).`
        : `None of the ${vulnerabilities.length} vulnerabilities could be automatically transformed; manual remediation is recommended.`,
  };
}

/**
 * Resolves a 1-based line number from any of the supported vulnerability fields.
 */
export function getTargetLineNumber(
  vulnerability: FixVulnerabilityInput
): number | undefined {
  const line =
    vulnerability.fileLine ?? vulnerability.line ?? vulnerability.location?.line;
  return typeof line === "number" && line >= 1 ? Math.floor(line) : undefined;
}

/**
 * Builds a lowercase searchable text string from vulnerability metadata for fixer matching.
 */
export function normalizeVulnerabilitySearchText(
  vulnerability: FixVulnerabilityInput
): string {
  return [
    vulnerability.ruleId,
    vulnerability.name ?? "",
    vulnerability.title ?? "",
    vulnerability.category,
    vulnerability.cweId ?? "",
    vulnerability.description ?? "",
    vulnerability.matchedText ?? "",
  ]
    .join(" ")
    .toLowerCase();
}

/**
 * Converts an identifier (e.g. `stripeApiKey`, `db-password`) into a valid UPPER_SNAKE_CASE env var name.
 */
export function toEnvVarName(rawIdentifier: string, fallback: string): string {
  const cleaned = rawIdentifier
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^a-zA-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toUpperCase();

  if (!cleaned || /^[0-9]/.test(cleaned)) {
    return fallback;
  }
  return cleaned;
}

/**
 * Extracts leading whitespace from a line of code.
 */
export function getIndentation(line: string): string {
  const match = /^(\s*)/.exec(line);
  return match?.[1] ?? "";
}

/**
 * Heuristic check for Python source code.
 */
export function isPythonCode(
  code: string,
  language?: SupportedLanguage
): boolean {
  if (language === "python") return true;
  if (language && language !== "unknown") return false;
  return /\bdef\s+\w+\s*\(|\bimport\s+(?:os|subprocess|hashlib)\b|:\s*#\s*python/m.test(
    code
  );
}

/**
 * Convenience builder for fixer results so every fixer returns a consistent envelope.
 * Supports both object params and legacy positional arguments.
 */
export function buildFixResult(params: {
  fixerId: string;
  originalCode: string;
  secureCode: string;
  severity: Severity;
  reason: string;
  summary: string;
  rationale?: string;
  notes?: string[];
}): SecureFixResult;
export function buildFixResult(
  originalCode: string,
  secureCode: string,
  fixerId: string,
  severity: Severity,
  summary: string,
  reason?: string,
  rationale?: string,
  notes?: string[]
): SecureFixResult;
export function buildFixResult(
  paramsOrOriginalCode:
    | {
        fixerId: string;
        originalCode: string;
        secureCode: string;
        severity: Severity;
        reason: string;
        summary: string;
        rationale?: string;
        notes?: string[];
      }
    | string,
  posSecureCode?: string,
  posFixerId?: string,
  posSeverity?: Severity,
  posSummary?: string,
  posReason?: string,
  posRationale?: string,
  posNotes?: string[]
): SecureFixResult {
  let params: {
    fixerId: string;
    originalCode: string;
    secureCode: string;
    severity: Severity;
    reason: string;
    summary: string;
    rationale?: string;
    notes?: string[];
  };

  if (typeof paramsOrOriginalCode === "string") {
    const summary = posSummary ?? "Applied security remediation.";
    params = {
      originalCode: paramsOrOriginalCode,
      secureCode: posSecureCode ?? paramsOrOriginalCode,
      fixerId: posFixerId ?? "unknown-fixer",
      severity: posSeverity ?? "medium",
      summary,
      reason: posReason ?? summary,
      ...(posRationale ? { rationale: posRationale } : {}),
      ...(posNotes ? { notes: posNotes } : {}),
    };
  } else {
    params = paramsOrOriginalCode;
  }

  const applied = params.secureCode !== params.originalCode;
  const { linesChanged, changedLineNumbers } = computeLineChanges(
    params.originalCode,
    params.secureCode,
    params.reason
  );

  return {
    originalCode: params.originalCode,
    secureCode: params.secureCode,
    linesChanged,
    changedLineNumbers,
    summary: applied
      ? params.summary
      : `No automatic code changes were required or matched by ${params.fixerId}.`,
    riskReduction: calculateRiskReduction(
      params.severity,
      applied,
      params.rationale
    ),
    fixerId: params.fixerId,
    applied,
    ...(params.notes && params.notes.length > 0 ? { notes: params.notes } : {}),
  };
}
