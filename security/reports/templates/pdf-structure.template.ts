import type {
  CanonicalSecurityReport,
  PdfCoverSection,
  PdfFixesTableRow,
  PdfFixesTableSection,
  PdfKpiCard,
  PdfKpiCardsSection,
  PdfPage,
  PdfReadyDocument,
  PdfRecommendationsListSection,
  PdfSection,
  PdfSeverityRow,
  PdfSeverityTableSection,
  PdfTimelineTableRow,
  PdfTimelineTableSection,
  PdfVulnerabilityCard,
  PdfVulnerabilityCardsSection,
} from "@/types/report-generator.types";

/**
 * Usable vertical content height on an A4 portrait page (842pt total)
 * after subtracting top/bottom margins (~102pt) and header/footer (~50pt).
 */
const A4_USABLE_HEIGHT_PT = 690;
const VULNERABILITIES_PER_SECTION_CHUNK = 4;

function formatLocationLabel(fileName?: string, line?: number, column?: number): string {
  const parts: string[] = [];
  if (fileName) {
    parts.push(fileName);
  }
  if (typeof line === "number") {
    parts.push(typeof column === "number" ? `L${line}:${column}` : `L${line}`);
  }
  return parts.length > 0 ? parts.join(" · ") : "N/A";
}

function getRiskTone(
  riskLevel: CanonicalSecurityReport["riskLevel"]
): PdfKpiCard["tone"] {
  switch (riskLevel) {
    case "critical":
    case "high":
      return "danger";
    case "moderate":
      return "warning";
    case "low":
      return "info";
    case "minimal":
    default:
      return "success";
  }
}

function paginateSections(sections: PdfSection[]): PdfPage[] {
  const pages: PdfPage[] = [];
  let currentSectionIds: string[] = [];
  let usedHeightPt = 0;

  const flushPage = () => {
    if (currentSectionIds.length > 0) {
      pages.push({
        pageNumber: pages.length + 1,
        sectionIds: currentSectionIds,
        usedHeightPt,
      });
      currentSectionIds = [];
      usedHeightPt = 0;
    }
  };

  for (const section of sections) {
    const height = Math.max(40, section.estimatedHeightPt);
    const exceedsCurrentPage =
      currentSectionIds.length > 0 && usedHeightPt + height > A4_USABLE_HEIGHT_PT;

    if (section.pageBreakBefore || exceedsCurrentPage) {
      flushPage();
    }

    currentSectionIds.push(section.id);
    usedHeightPt += height;
  }

  flushPage();

  if (pages.length === 0) {
    pages.push({ pageNumber: 1, sectionIds: [], usedHeightPt: 0 });
  }

  return pages;
}

/**
 * Builds a structured, paginated PDF layout AST/blueprint ready to feed into
 * React-PDF, Puppeteer, or PDFKit for binary PDF generation.
 */
export function buildPdfReadyStructure(
  report: CanonicalSecurityReport
): PdfReadyDocument {
  const { threatSummary, securityScore } = report;
  const sections: PdfSection[] = [];

  // 1. Cover block
  const coverSection: PdfCoverSection = {
    id: "section-cover",
    title: "Security Assessment Cover",
    type: "cover",
    keepTogether: true,
    estimatedHeightPt: 220,
    data: {
      reportId: report.reportId,
      reportTitle: `Sentinel AI Security Report`,
      subtitle: `${report.projectName} · Automated Security Posture Assessment`,
      projectName: report.projectName,
      developer: report.developer,
      date: report.date,
      securityScore: report.securityScore,
      riskLevel: report.riskLevel,
      metadata: report.metadata,
    },
  };
  sections.push(coverSection);

  // 2. KPI cards
  const kpiCards: PdfKpiCard[] = [
    {
      label: "Security Score",
      value: `${securityScore.percentage}% (${securityScore.letterGrade})`,
      sublabel: securityScore.securityLevel
        ? `Score ${securityScore.score} · ${securityScore.securityLevel}`
        : `Score ${securityScore.score}`,
      tone: getRiskTone(report.riskLevel),
    },
    {
      label: "Risk Level",
      value: report.riskLevel.toUpperCase(),
      sublabel: `${threatSummary.critical} critical · ${threatSummary.high} high`,
      tone: getRiskTone(report.riskLevel),
    },
    {
      label: "Detected Threats",
      value: String(threatSummary.totalDetected),
      sublabel: `${threatSummary.openIssues} open issues`,
      tone: threatSummary.openIssues > 0 ? "warning" : "success",
    },
    {
      label: "Fixes Applied",
      value: String(threatSummary.totalFixed),
      sublabel: `${report.fixesApplied.length} remediation record${report.fixesApplied.length === 1 ? "" : "s"}`,
      tone: threatSummary.totalFixed > 0 ? "success" : "neutral",
    },
  ];

  const kpiSection: PdfKpiCardsSection = {
    id: "section-kpi-cards",
    title: "Key Security Indicators",
    type: "kpi_cards",
    keepTogether: true,
    estimatedHeightPt: 110,
    data: {
      cards: kpiCards,
    },
  };
  sections.push(kpiSection);

  // 3. Severity breakdown table
  const denom = Math.max(1, threatSummary.totalDetected);
  const calcSeverityPct = (count: number): number =>
    threatSummary.totalDetected === 0
      ? 0
      : Math.min(100, Math.max(0, Math.round((count / denom) * 100)));

  const severityRows: PdfSeverityRow[] = [
    {
      severity: "critical",
      label: "Critical",
      count: threatSummary.critical,
      percentage: calcSeverityPct(threatSummary.critical),
    },
    {
      severity: "high",
      label: "High",
      count: threatSummary.high,
      percentage: calcSeverityPct(threatSummary.high),
    },
    {
      severity: "medium",
      label: "Medium",
      count: threatSummary.medium,
      percentage: calcSeverityPct(threatSummary.medium),
    },
    {
      severity: "low",
      label: "Low",
      count: threatSummary.low,
      percentage: calcSeverityPct(threatSummary.low),
    },
    {
      severity: "info",
      label: "Info",
      count: threatSummary.info,
      percentage: calcSeverityPct(threatSummary.info),
    },
  ];

  const severitySection: PdfSeverityTableSection = {
    id: "section-severity-table",
    title: "Executive Threat Summary & Severity Breakdown",
    type: "severity_table",
    keepTogether: true,
    estimatedHeightPt: 230,
    data: {
      executiveOverview: threatSummary.executiveOverview,
      columns: ["Severity", "Count", "Share (%)"],
      rows: severityRows,
      totals: {
        totalDetected: threatSummary.totalDetected,
        totalFixed: threatSummary.totalFixed,
        openIssues: threatSummary.openIssues,
      },
    },
  };
  sections.push(severitySection);

  // 4. Vulnerability cards (chunked for predictable pagination)
  const allVulnCards: PdfVulnerabilityCard[] = report.vulnerabilities.map(
    (vuln, index) => ({
      index: index + 1,
      ruleId: vuln.ruleId,
      title: vuln.title,
      severity: vuln.severity,
      status: vuln.status ?? "open",
      cweId: vuln.cweId,
      owaspCategory: vuln.owaspCategory,
      locationLabel: formatLocationLabel(vuln.fileName, vuln.line, vuln.column),
      description: vuln.description,
      snippet: vuln.snippet,
      remediationSummary: vuln.remediationSummary,
    })
  );

  if (allVulnCards.length === 0) {
    const emptyVulnSection: PdfVulnerabilityCardsSection = {
      id: "section-vulnerabilities-1",
      title: "Detected Vulnerabilities (0)",
      type: "vulnerability_cards",
      pageBreakBefore: true,
      estimatedHeightPt: 100,
      data: {
        totalCount: 0,
        cards: [],
      },
    };
    sections.push(emptyVulnSection);
  } else {
    for (
      let offset = 0;
      offset < allVulnCards.length;
      offset += VULNERABILITIES_PER_SECTION_CHUNK
    ) {
      const chunk = allVulnCards.slice(
        offset,
        offset + VULNERABILITIES_PER_SECTION_CHUNK
      );
      const chunkIndex = Math.floor(offset / VULNERABILITIES_PER_SECTION_CHUNK) + 1;
      const vulnSection: PdfVulnerabilityCardsSection = {
        id: `section-vulnerabilities-${chunkIndex}`,
        title:
          chunkIndex === 1
            ? `Detected Vulnerabilities (${allVulnCards.length})`
            : `Detected Vulnerabilities (Continued — Part ${chunkIndex})`,
        type: "vulnerability_cards",
        pageBreakBefore: chunkIndex === 1,
        estimatedHeightPt: 70 + chunk.length * 145,
        data: {
          totalCount: allVulnCards.length,
          cards: chunk,
        },
      };
      sections.push(vulnSection);
    }
  }

  // 5. Fixes Applied table
  const fixesRows: PdfFixesTableRow[] = report.fixesApplied.map((fix) => ({
    title: fix.title,
    summary: fix.summary,
    locationLabel: formatLocationLabel(fix.fileName, fix.line),
    riskReduction: fix.riskReduction,
    verified: Boolean(fix.verified),
    appliedAt: fix.appliedAt,
  }));

  const totalRiskReduction = fixesRows.reduce(
    (sum, row) => sum + row.riskReduction,
    0
  );

  const fixesSection: PdfFixesTableSection = {
    id: "section-fixes-table",
    title: `Fixes Applied (${fixesRows.length})`,
    type: "fixes_table",
    keepTogether: fixesRows.length <= 8,
    estimatedHeightPt: 90 + Math.max(1, fixesRows.length) * 36,
    data: {
      columns: ["Fix", "Summary", "Location", "Risk Reduction", "Verified"],
      rows: fixesRows,
      totalRiskReduction,
    },
  };
  sections.push(fixesSection);

  // 6. Security Timeline table
  const timelineRows: PdfTimelineTableRow[] = report.timeline.map((event) => ({
    timestamp: event.timestamp,
    formattedTime: event.formattedTime ?? event.timestamp,
    action: event.action,
    severity: event.severity,
    status: event.status,
    actor: event.actor,
    details: event.details,
  }));

  const timelineSection: PdfTimelineTableSection = {
    id: "section-timeline-table",
    title: `Security Timeline (${timelineRows.length})`,
    type: "timeline_table",
    keepTogether: timelineRows.length <= 8,
    estimatedHeightPt: 90 + Math.max(1, timelineRows.length) * 34,
    data: {
      columns: ["Timestamp", "Action", "Severity", "Status"],
      rows: timelineRows,
    },
  };
  sections.push(timelineSection);

  // 7. Prioritized Recommendations list
  const totalRecs =
    report.recommendations.immediate.length +
    report.recommendations.shortTerm.length +
    report.recommendations.longTerm.length;

  const recommendationsSection: PdfRecommendationsListSection = {
    id: "section-recommendations",
    title: "Prioritized Recommendations",
    type: "recommendations_list",
    estimatedHeightPt: 110 + Math.max(1, totalRecs) * 42,
    data: {
      groups: [
        {
          horizon: "immediate",
          heading: "Immediate Priority",
          items: report.recommendations.immediate,
        },
        {
          horizon: "short-term",
          heading: "Short-Term Priority",
          items: report.recommendations.shortTerm,
        },
        {
          horizon: "long-term",
          heading: "Long-Term Priority",
          items: report.recommendations.longTerm,
        },
      ],
    },
  };
  sections.push(recommendationsSection);

  const pages = paginateSections(sections);

  return {
    schemaVersion: "1.0.0",
    documentTitle: `Sentinel AI Security Report — ${report.projectName}`,
    author: report.developer.name,
    subject: `Security assessment report for ${report.projectName}`,
    createdAt: report.date.iso,
    pageSize: "A4",
    orientation: "portrait",
    margins: {
      top: 18,
      right: 16,
      bottom: 18,
      left: 16,
      unit: "mm",
    },
    theme: {
      primaryColor: "#0f172a",
      accentColor: "#2563eb",
      textColor: "#0f172a",
      mutedTextColor: "#475569",
      borderColor: "#e2e8f0",
      backgroundColor: "#ffffff",
      fontFamily: "Inter, Helvetica, Arial, sans-serif",
      monoFontFamily: "JetBrains Mono, Courier, monospace",
    },
    header: {
      left: "Sentinel AI Security Report",
      center: report.projectName,
      right: report.date.formatted,
      showPageNumbers: false,
    },
    footer: {
      left: `Report ID: ${report.reportId}`,
      center: `Risk Level: ${report.riskLevel.toUpperCase()}`,
      right: "Page {{page}} of {{totalPages}}",
      showPageNumbers: true,
    },
    sections,
    pages,
    totalPages: pages.length,
  };
}
