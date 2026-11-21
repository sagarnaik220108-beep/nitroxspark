/**
 * Domain types for the Sentinel AI Security Score Engine.
 * Defines inputs, scoring breakdowns, classifications, and output reports.
 */

export type RiskLevel = "minimal" | "low" | "moderate" | "high" | "critical";

export type RiskCategory =
  | "Minimal Risk"
  | "Low Risk"
  | "Moderate Risk"
  | "High Risk"
  | "Critical Risk";

export type LetterGrade = "A+" | "A" | "B" | "C" | "D" | "F";

export type SecurityLevel =
  | "Fortress"
  | "Hardened"
  | "Standard"
  | "Vulnerable"
  | "Exposed";

export type DeveloperLevel =
  | "Security Architect"
  | "Security Guardian"
  | "Active Defender"
  | "Security Apprentice"
  | "Needs Security Training";

export interface TimeSavedMetrics {
  /** Total engineering time saved in whole minutes. */
  minutes: number;
  /** Total engineering time saved in hours (rounded to 1 decimal place). */
  hours: number;
  /** Human-readable duration label, e.g. "2h 15m" or "45m". */
  formatted: string;
}

/**
 * Input metrics accepted by the Security Score Engine.
 */
export interface SecurityScoreInput {
  /** Optional pre-computed security score override (0-100, where 100 is most secure). */
  overallSecurityScore?: number;
  /** Optional explicit risk level override. Derived automatically when omitted. */
  riskLevel?: RiskLevel;
  /** Count of active/unresolved critical severity issues. */
  criticalIssues: number;
  /** Count of active/unresolved high severity issues. */
  highIssues: number;
  /** Count of active/unresolved medium severity issues. */
  mediumIssues: number;
  /** Count of active/unresolved low severity issues. */
  lowIssues: number;
  /** Total number of files scanned. */
  filesScanned: number;
  /** Total number of vulnerabilities or threats remediated. */
  threatsFixed: number;
  /**
   * Optional pre-computed time saved metrics.
   * When omitted, estimated automatically from `filesScanned` and `threatsFixed`.
   */
  timeSaved?: Partial<TimeSavedMetrics> & { minutes: number };
}

export interface SeverityPenaltyBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
  /** Sum of unweighted severity penalties before coverage scaling. */
  total: number;
  /** Effective penalty applied after multiplying by `scanCoverageFactor`. */
  effectiveTotal: number;
}

/**
 * Transparent breakdown showing how the final security score was derived.
 */
export interface ScoreBreakdown {
  /** Starting score before penalties and bonuses (default: 100). */
  baseScore: number;
  /** Per-severity and aggregate penalty breakdown. */
  severityPenalties: SeverityPenaltyBreakdown;
  /** Positive score credit earned from remediating threats (`threatsFixed`). */
  fixBonus: number;
  /**
   * Codebase scale factor in [0.5, 1.0] derived from `filesScanned`.
   * Larger scanned codebases dampen raw issue penalties proportionally.
   */
  scanCoverageFactor: number;
  /** Unclamped computed score before [0, 100] bounding. */
  rawScore: number;
  /** Final clamped 0-100 score. */
  finalScore: number;
  /** Indicates whether an explicit `overallSecurityScore` input override was used. */
  overrideApplied: boolean;
}

export interface SecurityScoreMetrics {
  criticalIssues: number;
  highIssues: number;
  mediumIssues: number;
  lowIssues: number;
  totalIssues: number;
  filesScanned: number;
  threatsFixed: number;
  /** Percentage of total encountered threats that have been fixed (0-100, 1 decimal). */
  fixRatePercentage: number;
  timeSaved: TimeSavedMetrics;
}

/**
 * Standardized output report produced by the Security Score Engine.
 */
export interface SecurityScoreReport {
  /** Final security posture score as a 0-100 integer (100 = most secure). */
  score: number;
  /** Alias for `score` (0-100 integer, where 100 is most secure). */
  overallSecurityScore: number;
  /** Security posture percentage (0.0 to 100.0, rounded to 1 decimal place). */
  percentage: number;
  /** Formatted percentage string, e.g. "86.0%". */
  percentageLabel: string;
  letterGrade: LetterGrade;
  riskLevel: RiskLevel;
  riskCategory: RiskCategory;
  securityLevel: SecurityLevel;
  developerLevel: DeveloperLevel;
  metrics: SecurityScoreMetrics;
  breakdown: ScoreBreakdown;
}

/**
 * Configurable weights and constants for `SecurityScoreEngine`.
 */
export interface SecurityScoreEngineConfig {
  baseScore: number;
  severityWeights: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  fixBonusPerThreat: number;
  maxFixBonus: number;
  minutesSavedPerFileScanned: number;
  minutesSavedPerThreatFixed: number;
}
