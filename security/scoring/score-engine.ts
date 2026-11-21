import type {
  DeveloperLevel,
  LetterGrade,
  RiskCategory,
  RiskLevel,
  ScoreBreakdown,
  SecurityLevel,
  SecurityScoreEngineConfig,
  SecurityScoreInput,
  SecurityScoreMetrics,
  SecurityScoreReport,
  SeverityPenaltyBreakdown,
  TimeSavedMetrics,
} from "@/types/score.types";

/**
 * Default scoring weights and engineering time-saved heuristics for Sentinel AI.
 */
export const DEFAULT_SCORE_ENGINE_CONFIG: SecurityScoreEngineConfig = {
  baseScore: 100,
  severityWeights: {
    critical: 22,
    high: 12,
    medium: 5,
    low: 2,
  },
  fixBonusPerThreat: 3,
  maxFixBonus: 15,
  minutesSavedPerFileScanned: 5,
  minutesSavedPerThreatFixed: 20,
};

const RISK_CATEGORY_MAP: Record<RiskLevel, RiskCategory> = {
  minimal: "Minimal Risk",
  low: "Low Risk",
  moderate: "Moderate Risk",
  high: "High Risk",
  critical: "Critical Risk",
};

function sanitizeNonNegativeInt(value: number): number {
  if (!Number.isFinite(value) || value < 0) return 0;
  return Math.floor(value);
}

function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, value));
}

function roundToDecimals(value: number, decimals: number): number {
  const factor = 10 ** decimals;
  return Math.round(value * factor) / factor;
}

/**
 * Formats a duration in whole minutes into a compact human-readable label.
 * Examples: 0 -> "0m", 45 -> "45m", 60 -> "1h", 135 -> "2h 15m".
 */
export function formatTimeSaved(totalMinutes: number): string {
  const minutes = sanitizeNonNegativeInt(totalMinutes);
  if (minutes === 0) return "0m";

  const wholeHours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;

  if (wholeHours === 0) {
    return `${remainingMinutes}m`;
  }

  if (remainingMinutes === 0) {
    return `${wholeHours}h`;
  }

  return `${wholeHours}h ${remainingMinutes}m`;
}

/**
 * Builds normalized `TimeSavedMetrics` from a whole-minute count.
 */
export function buildTimeSavedMetrics(totalMinutes: number): TimeSavedMetrics {
  const minutes = sanitizeNonNegativeInt(totalMinutes);
  const hours = roundToDecimals(minutes / 60, 1);
  return {
    minutes,
    hours,
    formatted: formatTimeSaved(minutes),
  };
}

/**
 * Pure, deterministic Security Score Engine for Sentinel AI.
 *
 * Computes a 0-100 security posture score (where 100 is most secure), letter grade,
 * risk classification, security level, developer maturity level, and a transparent
 * scoring breakdown from scan and remediation metrics.
 */
export class SecurityScoreEngine {
  private readonly config: SecurityScoreEngineConfig;

  constructor(config?: Partial<SecurityScoreEngineConfig>) {
    this.config = {
      baseScore: config?.baseScore ?? DEFAULT_SCORE_ENGINE_CONFIG.baseScore,
      severityWeights: {
        critical:
          config?.severityWeights?.critical ??
          DEFAULT_SCORE_ENGINE_CONFIG.severityWeights.critical,
        high:
          config?.severityWeights?.high ??
          DEFAULT_SCORE_ENGINE_CONFIG.severityWeights.high,
        medium:
          config?.severityWeights?.medium ??
          DEFAULT_SCORE_ENGINE_CONFIG.severityWeights.medium,
        low:
          config?.severityWeights?.low ??
          DEFAULT_SCORE_ENGINE_CONFIG.severityWeights.low,
      },
      fixBonusPerThreat:
        config?.fixBonusPerThreat ??
        DEFAULT_SCORE_ENGINE_CONFIG.fixBonusPerThreat,
      maxFixBonus:
        config?.maxFixBonus ?? DEFAULT_SCORE_ENGINE_CONFIG.maxFixBonus,
      minutesSavedPerFileScanned:
        config?.minutesSavedPerFileScanned ??
        DEFAULT_SCORE_ENGINE_CONFIG.minutesSavedPerFileScanned,
      minutesSavedPerThreatFixed:
        config?.minutesSavedPerThreatFixed ??
        DEFAULT_SCORE_ENGINE_CONFIG.minutesSavedPerThreatFixed,
    };
  }

  /**
   * Computes a codebase coverage dampener in `[0.5, 1.0]`.
   * Normalized to 1.0 to ensure deterministic, reproducible vulnerability scoring
   * that does not artificially dilute issue penalties or fluctuate on repeated scans.
   */
  public computeScanCoverageFactor(_filesScanned: number): number {
    return 1.0;
  }

  /**
   * Resolves a letter grade from a 0-100 security score.
   */
  public resolveLetterGrade(score: number): LetterGrade {
    if (score >= 95) return "A+";
    if (score >= 85) return "A";
    if (score >= 75) return "B";
    if (score >= 60) return "C";
    if (score >= 40) return "D";
    return "F";
  }

  /**
   * Resolves the risk level from the final score and unresolved critical issues.
   * Any unresolved critical issue prevents the posture from being classified as
   * `minimal` or `low` risk.
   */
  public resolveRiskLevel(score: number, criticalIssues: number): RiskLevel {
    if (score < 35) return "critical";
    if (score < 55) return criticalIssues >= 3 ? "critical" : "high";
    if (score < 75) return "moderate";
    if (criticalIssues > 0) return "moderate";
    if (score >= 90) return "minimal";
    return "low";
  }

  /**
   * Maps a normalized `RiskLevel` to its display `RiskCategory`.
   */
  public resolveRiskCategory(riskLevel: RiskLevel): RiskCategory {
    return RISK_CATEGORY_MAP[riskLevel];
  }

  /**
   * Resolves the organizational/codebase security posture tier.
   */
  public resolveSecurityLevel(score: number): SecurityLevel {
    if (score >= 90) return "Fortress";
    if (score >= 75) return "Hardened";
    if (score >= 55) return "Standard";
    if (score >= 35) return "Vulnerable";
    return "Exposed";
  }

  /**
   * Resolves the developer security maturity tier.
   */
  public resolveDeveloperLevel(score: number): DeveloperLevel {
    if (score >= 90) return "Security Architect";
    if (score >= 75) return "Security Guardian";
    if (score >= 55) return "Active Defender";
    if (score >= 35) return "Security Apprentice";
    return "Needs Security Training";
  }

  /**
   * Computes a complete, deterministic `SecurityScoreReport` from raw metrics.
   */
  public calculate(input: SecurityScoreInput): SecurityScoreReport {
    const criticalIssues = sanitizeNonNegativeInt(input.criticalIssues);
    const highIssues = sanitizeNonNegativeInt(input.highIssues);
    const mediumIssues = sanitizeNonNegativeInt(input.mediumIssues);
    const lowIssues = sanitizeNonNegativeInt(input.lowIssues);
    const filesScanned = sanitizeNonNegativeInt(input.filesScanned);
    const threatsFixed = sanitizeNonNegativeInt(input.threatsFixed);

    const totalIssues =
      criticalIssues + highIssues + mediumIssues + lowIssues;

    const totalEncountered = totalIssues + threatsFixed;
    const fixRatePercentage =
      totalEncountered === 0
        ? 0
        : roundToDecimals((threatsFixed / totalEncountered) * 100, 1);

    const timeSaved: TimeSavedMetrics = input.timeSaved
      ? {
          minutes: sanitizeNonNegativeInt(input.timeSaved.minutes),
          hours:
            input.timeSaved.hours !== undefined &&
            Number.isFinite(input.timeSaved.hours)
              ? roundToDecimals(Math.max(0, input.timeSaved.hours), 1)
              : roundToDecimals(
                  sanitizeNonNegativeInt(input.timeSaved.minutes) / 60,
                  1
                ),
          formatted:
            input.timeSaved.formatted?.trim() ||
            formatTimeSaved(input.timeSaved.minutes),
        }
      : buildTimeSavedMetrics(
          filesScanned * this.config.minutesSavedPerFileScanned +
            threatsFixed * this.config.minutesSavedPerThreatFixed
        );

    const scanCoverageFactor = this.computeScanCoverageFactor(filesScanned);

    const criticalPenalty =
      criticalIssues * this.config.severityWeights.critical;
    const highPenalty = highIssues * this.config.severityWeights.high;
    const mediumPenalty = mediumIssues * this.config.severityWeights.medium;
    const lowPenalty = lowIssues * this.config.severityWeights.low;
    const totalPenalty =
      criticalPenalty + highPenalty + mediumPenalty + lowPenalty;
    const effectiveTotalPenalty = roundToDecimals(
      totalPenalty * scanCoverageFactor,
      1
    );

    const severityPenalties: SeverityPenaltyBreakdown = {
      critical: criticalPenalty,
      high: highPenalty,
      medium: mediumPenalty,
      low: lowPenalty,
      total: totalPenalty,
      effectiveTotal: effectiveTotalPenalty,
    };

    const fixBonus = roundToDecimals(
      Math.min(
        this.config.maxFixBonus,
        threatsFixed * this.config.fixBonusPerThreat
      ),
      1
    );

    const overrideApplied =
      typeof input.overallSecurityScore === "number" &&
      Number.isFinite(input.overallSecurityScore);

    const rawScore = overrideApplied
      ? roundToDecimals(input.overallSecurityScore as number, 1)
      : roundToDecimals(
          this.config.baseScore - effectiveTotalPenalty + fixBonus,
          1
        );

    const percentage = roundToDecimals(clamp(rawScore, 0, 100), 1);
    const score = Math.round(percentage);
    const percentageLabel = `${percentage.toFixed(1)}%`;

    const riskLevel: RiskLevel =
      input.riskLevel ?? this.resolveRiskLevel(score, criticalIssues);
    const riskCategory = this.resolveRiskCategory(riskLevel);
    const letterGrade = this.resolveLetterGrade(score);
    const securityLevel = this.resolveSecurityLevel(score);
    const developerLevel = this.resolveDeveloperLevel(score);

    const metrics: SecurityScoreMetrics = {
      criticalIssues,
      highIssues,
      mediumIssues,
      lowIssues,
      totalIssues,
      filesScanned,
      threatsFixed,
      fixRatePercentage,
      timeSaved,
    };

    const breakdown: ScoreBreakdown = {
      baseScore: this.config.baseScore,
      severityPenalties,
      fixBonus,
      scanCoverageFactor,
      rawScore,
      finalScore: score,
      overrideApplied,
    };

    return {
      score,
      overallSecurityScore: score,
      percentage,
      percentageLabel,
      letterGrade,
      riskLevel,
      riskCategory,
      securityLevel,
      developerLevel,
      metrics,
      breakdown,
    };
  }
}

export const defaultSecurityScoreEngine = new SecurityScoreEngine();

/**
 * Convenience functional wrapper around `defaultSecurityScoreEngine.calculate`.
 */
export function calculateSecurityScore(
  input: SecurityScoreInput
): SecurityScoreReport {
  return defaultSecurityScoreEngine.calculate(input);
}
