import type {
  CanonicalSecurityReport,
  ContentDisposition,
  ExportFormat,
  GeneratedReportBundle,
  PdfReadyDocument,
  ReportDateInfo,
  ReportExportMetadata,
  ReportGeneratorInput,
  ReportOutputFormat,
  ReportRecommendationInput,
  ReportRecommendationItem,
  ReportRecommendations,
  ReportRiskLevel,
  ReportThreatSummary,
  ReportTimelineEvent,
  ReportVulnerabilityItem,
  SuggestedFileName,
} from "@/types/report-generator.types";
import type { Severity } from "@/types/security.types";
import {
  defaultReportTemplateRegistry,
  ReportTemplateRegistry,
} from "./templates";

const REPORT_VERSION = "1.0.0";

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function formatHumanDate(date: Date): string {
  return new Intl.DateTimeFormat("en-US", {
    year: "numeric",
    month: "long",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(date);
}

function normalizeDateInfo(inputDate?: string | Date): ReportDateInfo {
  const parsed =
    inputDate instanceof Date
      ? inputDate
      : typeof inputDate === "string"
        ? new Date(inputDate)
        : new Date();

  const validDate = Number.isNaN(parsed.getTime()) ? new Date() : parsed;

  return {
    iso: validDate.toISOString(),
    formatted: formatHumanDate(validDate),
  };
}

function slugifyProjectName(projectName: string): string {
  const slug = projectName
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
  return slug || "security-project";
}

function buildSuggestedFileName(
  projectName: string,
  isoDate: string,
  extension: string
): SuggestedFileName {
  const datePart = isoDate.slice(0, 10);
  const slug = slugifyProjectName(projectName);
  return `sentinel-report-${slug}-${datePart}.${extension}`;
}

function buildContentDisposition(
  fileName: SuggestedFileName,
  disposition: "attachment" | "inline" = "attachment"
): ContentDisposition {
  const safeFileName = fileName.replace(/["\r\n\\]/g, "");
  return `${disposition}; filename="${safeFileName}"`;
}

function deriveRiskLevel(
  scorePercentage: number,
  counts: { critical: number; high: number; medium: number; low: number }
): ReportRiskLevel {
  if (counts.critical > 0 || scorePercentage < 40) {
    return "critical";
  }
  if (counts.high > 0 || scorePercentage < 60) {
    return "high";
  }
  if (counts.medium > 0 || scorePercentage < 80) {
    return "moderate";
  }
  if (counts.low > 0 || scorePercentage < 95) {
    return "low";
  }
  return "minimal";
}

function buildExecutiveOverview(
  projectName: string,
  riskLevel: ReportRiskLevel,
  counts: {
    totalDetected: number;
    totalFixed: number;
    openIssues: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  }
): string {
  if (counts.totalDetected === 0) {
    return `Sentinel AI completed a security assessment of ${projectName} with zero detected vulnerabilities. Overall risk posture is ${riskLevel}.`;
  }

  return `Sentinel AI assessed ${projectName} and identified ${counts.totalDetected} security finding${counts.totalDetected === 1 ? "" : "s"} (${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low). ${counts.totalFixed} issue${counts.totalFixed === 1 ? " has" : "s have"} been remediated, leaving ${counts.openIssues} open issue${counts.openIssues === 1 ? "" : "s"}. Overall risk level is ${riskLevel.toUpperCase()}.`;
}

function normalizeRecommendationItem(
  item: ReportRecommendationInput,
  priority: "immediate" | "short-term" | "long-term"
): ReportRecommendationItem {
  if (typeof item === "string") {
    return {
      title: item.length > 80 ? `${item.slice(0, 77)}...` : item,
      description: item,
      priority,
      impact:
        priority === "immediate"
          ? "high"
          : priority === "short-term"
            ? "medium"
            : "low",
    };
  }
  return {
    ...item,
    priority: item.priority ?? priority,
  };
}

function buildRecommendations(
  inputRecs: ReportGeneratorInput["recommendations"],
  vulnerabilities: ReportVulnerabilityItem[]
): ReportRecommendations {
  const hasExplicitRecs =
    Boolean(inputRecs?.immediate?.length) ||
    Boolean(inputRecs?.shortTerm?.length) ||
    Boolean(inputRecs?.longTerm?.length);

  if (hasExplicitRecs) {
    return {
      immediate: (inputRecs?.immediate ?? []).map((item) =>
        normalizeRecommendationItem(item, "immediate")
      ),
      shortTerm: (inputRecs?.shortTerm ?? []).map((item) =>
        normalizeRecommendationItem(item, "short-term")
      ),
      longTerm: (inputRecs?.longTerm ?? []).map((item) =>
        normalizeRecommendationItem(item, "long-term")
      ),
    };
  }

  const immediate: ReportRecommendationItem[] = vulnerabilities
    .filter((v) => v.severity === "critical" || v.severity === "high")
    .slice(0, 6)
    .map((v) => ({
      title: `Remediate ${v.title}`,
      description:
        v.remediationSummary ??
        `Address ${v.severity} severity finding (${v.ruleId})${v.fileName ? ` in ${v.fileName}` : ""}.`,
      priority: "immediate",
      category: v.category,
      impact: "high",
    }));

  const shortTerm: ReportRecommendationItem[] = vulnerabilities
    .filter((v) => v.severity === "medium" || v.severity === "low")
    .slice(0, 6)
    .map((v) => ({
      title: `Harden against ${v.title}`,
      description:
        v.remediationSummary ??
        `Resolve ${v.severity} severity finding (${v.ruleId}) during the upcoming sprint.`,
      priority: "short-term",
      category: v.category,
      impact: v.severity === "medium" ? "medium" : "low",
    }));

  const longTerm: ReportRecommendationItem[] = [
    {
      title: "Automate Continuous Security Scanning in CI/CD",
      description:
        "Gate pull requests with automated static analysis and secret scanning to prevent regressions before merge.",
      priority: "long-term",
      category: "process",
      impact: "high",
    },
    {
      title: "Standardize Secure Coding Guardrails",
      description:
        "Adopt typed schema validation, parameterized queries, and strict output encoding across all service boundaries.",
      priority: "long-term",
      category: "architecture",
      impact: "medium",
    },
  ];

  return { immediate, shortTerm, longTerm };
}

function normalizeTimeline(
  inputTimeline: ReportTimelineEvent[] | undefined,
  reportDate: ReportDateInfo,
  developerName: string,
  riskLevel: ReportRiskLevel
): ReportTimelineEvent[] {
  const sourceEvents: ReportTimelineEvent[] =
    inputTimeline && inputTimeline.length > 0
      ? inputTimeline
      : [
          {
            timestamp: reportDate.iso,
            formattedTime: reportDate.formatted,
            action: "Security assessment report generated",
            severity:
              riskLevel === "critical"
                ? "critical"
                : riskLevel === "high"
                  ? "high"
                  : riskLevel === "moderate"
                    ? "medium"
                    : "info",
            status: "completed",
            actor: developerName,
          },
        ];

  return [...sourceEvents]
    .sort((a, b) => {
      const timeA = Date.parse(a.timestamp);
      const timeB = Date.parse(b.timestamp);
      if (Number.isNaN(timeA) || Number.isNaN(timeB)) {
        return a.timestamp.localeCompare(b.timestamp);
      }
      return timeA - timeB;
    })
    .map((event) => {
      const parsed = new Date(event.timestamp);
      return {
        ...event,
        formattedTime:
          event.formattedTime ??
          (Number.isNaN(parsed.getTime())
            ? event.timestamp
            : formatHumanDate(parsed)),
      };
    });
}

/**
 * Modular, template-based Security Report Generator.
 * Produces canonical JSON, XSS-safe print-friendly HTML5, and paginated
 * PDF-Ready AST structures along with clean export metadata descriptors.
 */
export class SecurityReportGenerator {
  private readonly registry: ReportTemplateRegistry;

  constructor(registry: ReportTemplateRegistry = defaultReportTemplateRegistry) {
    this.registry = registry;
  }

  /**
   * Normalizes raw report input into a deterministic CanonicalSecurityReport.
   */
  public buildCanonicalReport(
    input: ReportGeneratorInput
  ): CanonicalSecurityReport {
    const reportId = input.reportId?.trim() || crypto.randomUUID();
    const date = normalizeDateInfo(input.date);

    const sortedVulnerabilities = [...input.vulnerabilities].sort(
      (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
    );

    const fixesApplied = [...(input.fixesApplied ?? [])];

    const computedCounts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    let fixedVulnCount = 0;
    for (const vuln of sortedVulnerabilities) {
      computedCounts[vuln.severity] += 1;
      if (vuln.status === "fixed") {
        fixedVulnCount += 1;
      }
    }

    const totalDetected =
      input.threatSummary?.totalDetected ?? sortedVulnerabilities.length;
    const totalFixed =
      input.threatSummary?.totalFixed ??
      Math.max(fixedVulnCount, fixesApplied.length);
    const openIssues =
      input.threatSummary?.openIssues ??
      Math.max(0, totalDetected - totalFixed);

    const critical = input.threatSummary?.critical ?? computedCounts.critical;
    const high = input.threatSummary?.high ?? computedCounts.high;
    const medium = input.threatSummary?.medium ?? computedCounts.medium;
    const low = input.threatSummary?.low ?? computedCounts.low;
    const info = input.threatSummary?.info ?? computedCounts.info;

    const riskLevel: ReportRiskLevel =
      input.riskLevel ??
      deriveRiskLevel(input.securityScore.percentage, {
        critical,
        high,
        medium,
        low,
      });

    const executiveOverview =
      input.threatSummary?.executiveOverview?.trim() ||
      buildExecutiveOverview(input.projectName, riskLevel, {
        totalDetected,
        totalFixed,
        openIssues,
        critical,
        high,
        medium,
        low,
      });

    const threatSummary: ReportThreatSummary = {
      totalDetected,
      totalFixed,
      openIssues,
      critical,
      high,
      medium,
      low,
      info,
      executiveOverview,
    };

    const recommendations = buildRecommendations(
      input.recommendations,
      sortedVulnerabilities
    );

    const timeline = normalizeTimeline(
      input.timeline,
      date,
      input.developer.name,
      riskLevel
    );

    return {
      reportId,
      reportVersion: REPORT_VERSION,
      projectName: input.projectName.trim(),
      developer: {
        name: input.developer.name.trim(),
        ...(input.developer.email ? { email: input.developer.email.trim() } : {}),
        ...(input.developer.role ? { role: input.developer.role.trim() } : {}),
      },
      date,
      securityScore: {
        score: input.securityScore.score,
        percentage: input.securityScore.percentage,
        letterGrade: input.securityScore.letterGrade,
        ...(input.securityScore.securityLevel
          ? { securityLevel: input.securityScore.securityLevel }
          : {}),
      },
      riskLevel,
      threatSummary,
      vulnerabilities: sortedVulnerabilities,
      fixesApplied,
      recommendations,
      timeline,
      ...(input.metadata ? { metadata: input.metadata } : {}),
    };
  }

  /**
   * Generates the requested format(s) ("json" | "html" | "pdf" | "all") along
   * with standardized export descriptors.
   */
  public generate(
    input: ReportGeneratorInput,
    format: ReportOutputFormat = "all"
  ): GeneratedReportBundle {
    const canonical = this.buildCanonicalReport(input);
    const encoder = new TextEncoder();

    const bundle: GeneratedReportBundle = {
      reportId: canonical.reportId,
      generatedAt: canonical.date.iso,
      canonical,
      exportMetadata: {},
    };

    const includeFormat = (target: ExportFormat): boolean =>
      format === "all" || format === target;

    if (includeFormat("json")) {
      const jsonContent = this.registry.render<CanonicalSecurityReport>(
        "json",
        canonical
      );
      const serialized = JSON.stringify(jsonContent, null, 2);
      const fileName = buildSuggestedFileName(
        canonical.projectName,
        canonical.date.iso,
        "json"
      );
      const meta: ReportExportMetadata = {
        format: "json",
        fileName,
        mimeType: "application/json",
        contentDisposition: buildContentDisposition(fileName, "attachment"),
        extension: "json",
        byteLength: encoder.encode(serialized).length,
        generatedAt: canonical.date.iso,
      };
      bundle.json = {
        content: jsonContent,
        serialized,
        exportMetadata: meta,
      };
      bundle.exportMetadata.json = meta;
    }

    if (includeFormat("html")) {
      const htmlContent = this.registry.render<string>("html", canonical);
      const fileName = buildSuggestedFileName(
        canonical.projectName,
        canonical.date.iso,
        "html"
      );
      const meta: ReportExportMetadata = {
        format: "html",
        fileName,
        mimeType: "text/html",
        contentDisposition: buildContentDisposition(fileName, "attachment"),
        extension: "html",
        byteLength: encoder.encode(htmlContent).length,
        generatedAt: canonical.date.iso,
      };
      bundle.html = {
        content: htmlContent,
        exportMetadata: meta,
      };
      bundle.exportMetadata.html = meta;
    }

    if (includeFormat("pdf")) {
      const pdfDocument = this.registry.render<PdfReadyDocument>(
        "pdf",
        canonical
      );
      const serializedPdfAst = JSON.stringify(pdfDocument);
      const fileName = buildSuggestedFileName(
        canonical.projectName,
        canonical.date.iso,
        "pdf"
      );
      const meta: ReportExportMetadata = {
        format: "pdf",
        fileName,
        mimeType: "application/pdf",
        contentDisposition: buildContentDisposition(fileName, "attachment"),
        extension: "pdf",
        byteLength: encoder.encode(serializedPdfAst).length,
        generatedAt: canonical.date.iso,
      };
      bundle.pdfReady = {
        content: pdfDocument,
        exportMetadata: meta,
      };
      bundle.exportMetadata.pdf = meta;
    }

    return bundle;
  }

  /**
   * Renders a report through any custom template registered in the registry
   * (e.g., SARIF, CSV, DOCX).
   */
  public renderCustomFormat<TOutput = unknown>(
    format: string,
    input: ReportGeneratorInput
  ): TOutput {
    const canonical = this.buildCanonicalReport(input);
    return this.registry.render<TOutput>(format, canonical);
  }

  public getTemplateRegistry(): ReportTemplateRegistry {
    return this.registry;
  }
}

export const defaultReportGenerator = new SecurityReportGenerator();
