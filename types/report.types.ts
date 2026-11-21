import type {
  AttackSimulationResult,
  DetectedVulnerability,
  SeverityBreakdown,
  SupportedLanguage,
} from "./security.types";

export type ReportFormat = "json" | "markdown";

export interface ComplianceMapping {
  standard: "OWASP Top 10 (2021)" | "CWE Top 25" | "NIST SSDF";
  controlsAffected: string[];
  status: "pass" | "warning" | "fail";
}

export interface SecurityReportPayload {
  reportVersion: string;
  generatedAt: string;
  scanId: string;
  projectName: string;
  fileName: string;
  language: SupportedLanguage;
  executiveSummary: {
    overallRiskScore: number;
    riskGrade: "A" | "B" | "C" | "D" | "F";
    totalVulnerabilities: number;
    severityBreakdown: SeverityBreakdown;
    postureStatement: string;
    topPriorities: string[];
  };
  compliance: ComplianceMapping[];
  findings: DetectedVulnerability[];
  attackSimulations: AttackSimulationResult[];
  remediationRoadmap: {
    immediate: string[];
    shortTerm: string[];
    longTerm: string[];
  };
}

export interface GeneratedReport {
  id: string;
  scanId: string;
  userId: string;
  title: string;
  format: ReportFormat;
  payload: SecurityReportPayload;
  markdownContent?: string;
  createdAt: string;
}
