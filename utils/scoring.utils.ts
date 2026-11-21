import type {
  DetectedVulnerability,
  Severity,
  SeverityBreakdown,
} from "@/types";

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 30,
  high: 18,
  medium: 9,
  low: 4,
  info: 1,
};

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_RANK[b] - SEVERITY_RANK[a];
}

export function buildSeverityBreakdown(
  vulnerabilities: Pick<DetectedVulnerability, "severity">[]
): SeverityBreakdown {
  const breakdown: SeverityBreakdown = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const vuln of vulnerabilities) {
    breakdown[vuln.severity] += 1;
  }

  return breakdown;
}

/**
 * Computes a bounded 0-100 risk score weighted by severity and confidence.
 * 0 = clean, 100 = critical exposure.
 */
export function calculateRiskScore(
  vulnerabilities: Pick<DetectedVulnerability, "severity" | "confidence">[]
): number {
  if (vulnerabilities.length === 0) return 0;

  let rawScore = 0;
  for (const vuln of vulnerabilities) {
    const weight = SEVERITY_WEIGHTS[vuln.severity];
    const confidenceFactor = Math.max(0.5, Math.min(1, vuln.confidence));
    rawScore += weight * confidenceFactor;
  }

  // Smooth diminishing-returns curve capped at 100
  const normalized = Math.round(100 * (1 - Math.exp(-rawScore / 45)));
  return Math.max(1, Math.min(100, normalized));
}

export function calculateRiskGrade(
  riskScore: number
): "A" | "B" | "C" | "D" | "F" {
  if (riskScore <= 10) return "A";
  if (riskScore <= 30) return "B";
  if (riskScore <= 55) return "C";
  if (riskScore <= 75) return "D";
  return "F";
}

export function buildScanSummary(
  breakdown: SeverityBreakdown,
  riskScore: number,
  riskGrade: "A" | "B" | "C" | "D" | "F"
): string {
  const total =
    breakdown.critical +
    breakdown.high +
    breakdown.medium +
    breakdown.low +
    breakdown.info;

  if (total === 0) {
    return "No known security vulnerabilities were detected by the active rule set. Risk grade: A (0/100).";
  }

  const parts: string[] = [];
  if (breakdown.critical > 0) parts.push(`${breakdown.critical} critical`);
  if (breakdown.high > 0) parts.push(`${breakdown.high} high`);
  if (breakdown.medium > 0) parts.push(`${breakdown.medium} medium`);
  if (breakdown.low > 0) parts.push(`${breakdown.low} low`);
  if (breakdown.info > 0) parts.push(`${breakdown.info} info`);

  return `Detected ${total} potential security issue${total === 1 ? "" : "s"} (${parts.join(", ")}). Overall risk score: ${riskScore}/100 (Grade ${riskGrade}).`;
}
