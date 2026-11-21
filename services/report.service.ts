import type {
  AttackSimulationResult,
  ComplianceMapping,
  DetectedVulnerability,
  PaginationMeta,
  SecurityReportPayload,
  SecurityReportRow,
  VulnerabilityRow,
} from "@/types";
import {
  AuditRepository,
  ReportRepository,
  ScanRepository,
  SimulationRepository,
  VulnerabilityRepository,
} from "@/database/repositories";
import { simulateAttackForVulnerability } from "@/security";
import {
  generateReportSchema,
  paginationQuerySchema,
  parseOrThrow,
  uuidParamSchema,
} from "@/utils";
import { authService } from "./auth.service";

function mapVulnerabilityRow(row: VulnerabilityRow): DetectedVulnerability {
  return {
    ruleId: row.rule_id,
    title: row.title,
    description: row.description,
    explanation: row.explanation,
    severity: row.severity,
    category: row.category,
    cweId: row.cwe_id,
    owaspCategory: row.owasp_category,
    confidence: Number(row.confidence),
    location: {
      line: row.line_start,
      column: row.column_start,
      endLine: row.line_end,
      endColumn: row.column_end,
      snippet: row.code_snippet,
    },
    matchedText: row.matched_text,
    remediation: row.remediation,
  };
}

function buildComplianceMappings(
  findings: DetectedVulnerability[]
): ComplianceMapping[] {
  const owaspAffected = Array.from(new Set(findings.map((f) => f.owaspCategory)));
  const cweAffected = Array.from(new Set(findings.map((f) => f.cweId)));
  const hasHighOrCritical = findings.some(
    (f) => f.severity === "critical" || f.severity === "high"
  );

  const status: "pass" | "warning" | "fail" =
    findings.length === 0 ? "pass" : hasHighOrCritical ? "fail" : "warning";

  return [
    {
      standard: "OWASP Top 10 (2021)",
      controlsAffected: owaspAffected,
      status,
    },
    {
      standard: "CWE Top 25",
      controlsAffected: cweAffected,
      status,
    },
    {
      standard: "NIST SSDF",
      controlsAffected:
        findings.length === 0
          ? []
          : ["PW.7 - Review and/or Analyze Human-Readable Code", "PW.8 - Test Executable Code"],
      status,
    },
  ];
}

function renderReportMarkdown(payload: SecurityReportPayload): string {
  const lines: string[] = [
    `# Sentinel AI Security Report`,
    "",
    `- **Project**: ${payload.projectName}`,
    `- **File**: \`${payload.fileName}\``,
    `- **Language**: \`${payload.language}\``,
    `- **Scan ID**: \`${payload.scanId}\``,
    `- **Generated At**: ${payload.generatedAt}`,
    `- **Overall Risk Score**: **${payload.executiveSummary.overallRiskScore}/100 (Grade ${payload.executiveSummary.riskGrade})**`,
    "",
    `## Executive Summary`,
    "",
    payload.executiveSummary.postureStatement,
    "",
    `| Severity | Count |`,
    `| --- | ---: |`,
    `| Critical | ${payload.executiveSummary.severityBreakdown.critical} |`,
    `| High | ${payload.executiveSummary.severityBreakdown.high} |`,
    `| Medium | ${payload.executiveSummary.severityBreakdown.medium} |`,
    `| Low | ${payload.executiveSummary.severityBreakdown.low} |`,
    `| Info | ${payload.executiveSummary.severityBreakdown.info} |`,
    "",
    `## Findings (${payload.findings.length})`,
    "",
  ];

  if (payload.findings.length === 0) {
    lines.push("No vulnerabilities detected.");
  } else {
    for (const [index, finding] of payload.findings.entries()) {
      lines.push(
        `### ${index + 1}. [${finding.severity.toUpperCase()}] ${finding.title}`,
        `- **Rule ID**: \`${finding.ruleId}\` | **CWE**: \`${finding.cweId}\` | **OWASP**: ${finding.owaspCategory}`,
        `- **Location**: Line ${finding.location.line}, Column ${finding.location.column}`,
        "",
        `**Explanation**: ${finding.explanation}`,
        "",
        "```",
        finding.location.snippet,
        "```",
        "",
        `**Recommended Fix**: ${finding.remediation.summary}`,
        "",
        "```",
        finding.remediation.secureCodeExample,
        "```",
        ""
      );
    }
  }

  if (payload.attackSimulations.length > 0) {
    lines.push(`## Defensive Attack Simulations`, "");
    for (const sim of payload.attackSimulations) {
      lines.push(
        `### ${sim.attackName} (\`${sim.ruleId}\`)`,
        `- **MITRE ATT&CK**: ${sim.mitreAttackTechnique}`,
        `- **Blast Radius**: ${sim.blastRadius} | **Likelihood**: ${sim.likelihood}`,
        `- **Simulated Payload**: \`${sim.simulatedPayload}\``,
        ""
      );
    }
  }

  return lines.join("\n");
}

/**
 * ReportService builds executive and technical security reports in JSON and
 * Markdown formats, persists them in Supabase, and supports report retrieval.
 */
export class ReportService {
  public async generateReport(rawInput: unknown): Promise<SecurityReportRow> {
    const input = parseOrThrow(generateReportSchema, rawInput);
    const { user, supabase } = await authService.requireAuthenticatedUser();

    const scanRepo = new ScanRepository(supabase);
    const vulnRepo = new VulnerabilityRepository(supabase);
    const simRepo = new SimulationRepository(supabase);
    const reportRepo = new ReportRepository(supabase);
    const auditRepo = new AuditRepository(supabase);

    const scan = await scanRepo.findById(input.scanId, user.id);
    const vulnRows = await vulnRepo.findByScanId(scan.id, user.id);
    const findings = vulnRows.map(mapVulnerabilityRow);

    let attackSimulations: AttackSimulationResult[] = [];
    if (input.includeSimulations) {
      const existingSims = await simRepo.findByScanId(scan.id, user.id);
      if (existingSims.length > 0) {
        attackSimulations = existingSims.map((row) => row.simulation_payload);
      } else {
        attackSimulations = findings.map((finding, idx) =>
          simulateAttackForVulnerability(finding, vulnRows[idx]?.id)
        );
      }
    }

    const immediate = findings
      .filter((f) => f.severity === "critical" || f.severity === "high")
      .map((f) => `[Line ${f.location.line}] ${f.title}: ${f.remediation.summary}`);

    const shortTerm = findings
      .filter((f) => f.severity === "medium")
      .map((f) => `[Line ${f.location.line}] ${f.title}: ${f.remediation.summary}`);

    const longTerm = [
      "Integrate Sentinel AI into CI/CD pull request checks to catch vulnerabilities before merge.",
      "Maintain custom organizational security rules for proprietary APIs and internal patterns.",
      "Enforce strict Supabase Row-Level Security (RLS) and Zod input validation across all routes.",
    ];

    const payload: SecurityReportPayload = {
      reportVersion: "1.0.0",
      generatedAt: new Date().toISOString(),
      scanId: scan.id,
      projectName: scan.project_name,
      fileName: scan.file_name,
      language: scan.language,
      executiveSummary: {
        overallRiskScore: scan.risk_score,
        riskGrade: scan.risk_grade,
        totalVulnerabilities: findings.length,
        severityBreakdown: scan.severity_breakdown,
        postureStatement: scan.summary,
        topPriorities: immediate.slice(0, 5),
      },
      compliance: buildComplianceMappings(findings),
      findings,
      attackSimulations,
      remediationRoadmap: {
        immediate,
        shortTerm,
        longTerm,
      },
    };

    const markdownContent =
      input.format === "markdown" ? renderReportMarkdown(payload) : null;

    const title =
      input.title ?? `Security Report — ${scan.project_name} (${scan.file_name})`;

    const report = await reportRepo.create({
      scan_id: scan.id,
      user_id: user.id,
      title,
      format: input.format,
      report_payload: payload,
      markdown_content: markdownContent,
    });

    await auditRepo.record({
      userId: user.id,
      action: "report.generated",
      resourceType: "security_report",
      resourceId: report.id,
      metadata: {
        scanId: scan.id,
        format: input.format,
        findingsCount: findings.length,
      },
    });

    return report;
  }

  public async getReportById(reportId: string): Promise<SecurityReportRow> {
    const validId = parseOrThrow(uuidParamSchema, reportId);
    const { user, supabase } = await authService.requireAuthenticatedUser();
    const reportRepo = new ReportRepository(supabase);
    return reportRepo.findById(validId, user.id);
  }

  public async listUserReports(rawQuery: unknown): Promise<{
    reports: SecurityReportRow[];
    pagination: PaginationMeta;
  }> {
    const { page, pageSize } = parseOrThrow(paginationQuerySchema, rawQuery);
    const { user, supabase } = await authService.requireAuthenticatedUser();
    const reportRepo = new ReportRepository(supabase);

    const { items, total } = await reportRepo.listByUser(
      user.id,
      page,
      pageSize
    );

    return {
      reports: items,
      pagination: {
        page,
        pageSize,
        total,
        totalPages: Math.max(1, Math.ceil(total / pageSize)),
      },
    };
  }

  public async deleteReport(reportId: string): Promise<{ deletedId: string }> {
    const validId = parseOrThrow(uuidParamSchema, reportId);
    const { user, supabase } = await authService.requireAuthenticatedUser();

    const reportRepo = new ReportRepository(supabase);
    const auditRepo = new AuditRepository(supabase);

    await reportRepo.delete(validId, user.id);
    await auditRepo.record({
      userId: user.id,
      action: "report.deleted",
      resourceType: "security_report",
      resourceId: validId,
    });

    return { deletedId: validId };
  }
}

export const reportService = new ReportService();
