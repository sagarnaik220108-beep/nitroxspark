import type {
  Severity,
  SupportedLanguage,
  VulnerabilityCategory,
  VulnerabilityStatus,
} from "./security.types";

/**
 * Supported concrete export formats for generated reports.
 */
export type ExportFormat = "json" | "html" | "pdf";

/**
 * Supported format request options for the report generator and API route.
 */
export type ReportOutputFormat = ExportFormat | "all";

/**
 * Suggested download file name for an exported report artifact.
 */
export type SuggestedFileName = string;

/**
 * Standard HTTP Content-Disposition header value for report downloads.
 */
export type ContentDisposition =
  | `attachment; filename="${string}"`
  | `inline; filename="${string}"`;

/**
 * Overall risk classification for a security report.
 */
export type ReportRiskLevel = "minimal" | "low" | "moderate" | "high" | "critical";

/**
 * Developer / author metadata attached to a security report.
 */
export interface ReportDeveloper {
  name: string;
  email?: string;
  role?: string;
}

/**
 * Dual-format date representation (ISO 8601 + human-readable).
 */
export interface ReportDateInfo {
  iso: string;
  formatted: string;
}

/**
 * Security score summary included in the report.
 */
export interface ReportSecurityScore {
  score: number;
  percentage: number;
  letterGrade: string;
  securityLevel?: string;
}

/**
 * Aggregated threat and severity summary for executive and technical views.
 */
export interface ReportThreatSummary {
  totalDetected: number;
  totalFixed: number;
  openIssues: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  executiveOverview: string;
}

/**
 * Structured vulnerability entry inside a generated security report.
 */
export interface ReportVulnerabilityItem {
  id?: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  category?: VulnerabilityCategory | string;
  cweId?: string;
  owaspCategory?: string;
  status?: VulnerabilityStatus;
  fileName?: string;
  line?: number;
  column?: number;
  snippet?: string;
  explanation?: string;
  remediationSummary?: string;
  confidence?: number;
}

/**
 * Structured applied fix entry with summary and quantified risk reduction.
 */
export interface ReportFixAppliedItem {
  id?: string;
  vulnerabilityId?: string;
  ruleId?: string;
  title: string;
  summary: string;
  fileName?: string;
  line?: number;
  riskReduction: number;
  appliedAt?: string;
  appliedBy?: string;
  verified?: boolean;
}

/**
 * Prioritized recommendation entry.
 */
export interface ReportRecommendationItem {
  title: string;
  description: string;
  priority: "immediate" | "short-term" | "long-term";
  category?: string;
  impact?: "high" | "medium" | "low";
}

/**
 * Prioritized remediation roadmap grouped by time horizon.
 */
export interface ReportRecommendations {
  immediate: ReportRecommendationItem[];
  shortTerm: ReportRecommendationItem[];
  longTerm: ReportRecommendationItem[];
}

/**
 * Timeline status values for security workflow events.
 */
export type TimelineEventStatus =
  | "completed"
  | "in_progress"
  | "pending"
  | "failed"
  | "blocked"
  | "info";

/**
 * Ordered security timeline event.
 */
export interface ReportTimelineEvent {
  timestamp: string;
  formattedTime?: string;
  action: string;
  severity: Severity;
  status: TimelineEventStatus;
  actor?: string;
  details?: string;
}

/**
 * Optional source/scan context metadata attached to the report.
 */
export interface ReportSourceMetadata {
  scanId?: string;
  fileName?: string;
  language?: SupportedLanguage | string;
  branch?: string;
  commitSha?: string;
  environment?: string;
}

/**
 * Flexible recommendation input (accepts plain string or structured item).
 */
export type ReportRecommendationInput = string | ReportRecommendationItem;

/**
 * Input contract accepted by SecurityReportGenerator.
 * Optional computed fields (such as date, riskLevel, threatSummary counts, or
 * default recommendations) are normalized and derived automatically when omitted.
 */
export interface ReportGeneratorInput {
  reportId?: string;
  projectName: string;
  developer: ReportDeveloper;
  date?: string | Date;
  securityScore: ReportSecurityScore;
  riskLevel?: ReportRiskLevel;
  threatSummary?: Partial<ReportThreatSummary>;
  vulnerabilities: ReportVulnerabilityItem[];
  fixesApplied?: ReportFixAppliedItem[];
  recommendations?: {
    immediate?: ReportRecommendationInput[];
    shortTerm?: ReportRecommendationInput[];
    longTerm?: ReportRecommendationInput[];
  };
  timeline?: ReportTimelineEvent[];
  metadata?: ReportSourceMetadata;
}

/**
 * Canonical normalized Security Report structure used as the single source of
 * truth across JSON, HTML, PDF-Ready, and future custom report templates.
 */
export interface CanonicalSecurityReport {
  reportId: string;
  reportVersion: string;
  projectName: string;
  developer: ReportDeveloper;
  date: ReportDateInfo;
  securityScore: ReportSecurityScore;
  riskLevel: ReportRiskLevel;
  threatSummary: ReportThreatSummary;
  vulnerabilities: ReportVulnerabilityItem[];
  fixesApplied: ReportFixAppliedItem[];
  recommendations: ReportRecommendations;
  timeline: ReportTimelineEvent[];
  metadata?: ReportSourceMetadata;
}

/**
 * Export descriptor metadata enabling clean client downloads and storage later.
 */
export interface ReportExportMetadata {
  format: ExportFormat;
  fileName: SuggestedFileName;
  mimeType: string;
  contentDisposition: ContentDisposition;
  extension: string;
  byteLength: number;
  generatedAt: string;
}

/**
 * PDF page sizing and layout primitives.
 */
export type PdfPageSize = "A4" | "Letter";
export type PdfPageOrientation = "portrait" | "landscape";

export interface PdfMargins {
  top: number;
  right: number;
  bottom: number;
  left: number;
  unit: "mm" | "pt";
}

export interface PdfHeaderFooter {
  left: string;
  center?: string;
  right: string;
  showPageNumbers?: boolean;
}

export interface PdfTheme {
  primaryColor: string;
  accentColor: string;
  textColor: string;
  mutedTextColor: string;
  borderColor: string;
  backgroundColor: string;
  fontFamily: string;
  monoFontFamily: string;
}

export interface PdfSectionBase {
  id: string;
  title: string;
  pageBreakBefore?: boolean;
  keepTogether?: boolean;
  estimatedHeightPt: number;
}

export interface PdfCoverSection extends PdfSectionBase {
  type: "cover";
  data: {
    reportId: string;
    reportTitle: string;
    subtitle: string;
    projectName: string;
    developer: ReportDeveloper;
    date: ReportDateInfo;
    securityScore: ReportSecurityScore;
    riskLevel: ReportRiskLevel;
    metadata?: ReportSourceMetadata;
  };
}

export interface PdfKpiCard {
  label: string;
  value: string;
  sublabel?: string;
  tone: "neutral" | "success" | "warning" | "danger" | "info";
}

export interface PdfKpiCardsSection extends PdfSectionBase {
  type: "kpi_cards";
  data: {
    cards: PdfKpiCard[];
  };
}

export interface PdfSeverityRow {
  severity: Severity;
  label: string;
  count: number;
  percentage: number;
}

export interface PdfSeverityTableSection extends PdfSectionBase {
  type: "severity_table";
  data: {
    executiveOverview: string;
    columns: readonly string[];
    rows: PdfSeverityRow[];
    totals: {
      totalDetected: number;
      totalFixed: number;
      openIssues: number;
    };
  };
}

export interface PdfVulnerabilityCard {
  index: number;
  ruleId: string;
  title: string;
  severity: Severity;
  status: VulnerabilityStatus;
  cweId?: string;
  owaspCategory?: string;
  locationLabel?: string;
  description: string;
  snippet?: string;
  remediationSummary?: string;
}

export interface PdfVulnerabilityCardsSection extends PdfSectionBase {
  type: "vulnerability_cards";
  data: {
    totalCount: number;
    cards: PdfVulnerabilityCard[];
  };
}

export interface PdfFixesTableRow {
  title: string;
  summary: string;
  locationLabel: string;
  riskReduction: number;
  verified: boolean;
  appliedAt?: string;
}

export interface PdfFixesTableSection extends PdfSectionBase {
  type: "fixes_table";
  data: {
    columns: readonly string[];
    rows: PdfFixesTableRow[];
    totalRiskReduction: number;
  };
}

export interface PdfTimelineTableRow {
  timestamp: string;
  formattedTime: string;
  action: string;
  severity: Severity;
  status: TimelineEventStatus;
  actor?: string;
  details?: string;
}

export interface PdfTimelineTableSection extends PdfSectionBase {
  type: "timeline_table";
  data: {
    columns: readonly string[];
    rows: PdfTimelineTableRow[];
  };
}

export interface PdfRecommendationsListSection extends PdfSectionBase {
  type: "recommendations_list";
  data: {
    groups: {
      horizon: "immediate" | "short-term" | "long-term";
      heading: string;
      items: ReportRecommendationItem[];
    }[];
  };
}

/**
 * Discriminated union of all structured PDF layout AST sections.
 */
export type PdfSection =
  | PdfCoverSection
  | PdfKpiCardsSection
  | PdfSeverityTableSection
  | PdfVulnerabilityCardsSection
  | PdfFixesTableSection
  | PdfTimelineTableSection
  | PdfRecommendationsListSection;

/**
 * Logical page mapping produced by the PDF pagination planner.
 */
export interface PdfPage {
  pageNumber: number;
  sectionIds: string[];
  usedHeightPt: number;
}

/**
 * Structured, paginated PDF layout AST/blueprint ready to feed into
 * React-PDF, Puppeteer, or PDFKit for binary PDF rendering.
 */
export interface PdfReadyDocument {
  schemaVersion: "1.0.0";
  documentTitle: string;
  author: string;
  subject: string;
  createdAt: string;
  pageSize: PdfPageSize;
  orientation: PdfPageOrientation;
  margins: PdfMargins;
  theme: PdfTheme;
  header: PdfHeaderFooter;
  footer: PdfHeaderFooter;
  sections: PdfSection[];
  pages: PdfPage[];
  totalPages: number;
}

/**
 * Generic pluggable template definition for extending report output formats.
 */
export interface ReportTemplate<TOutput = unknown> {
  readonly format: string;
  readonly mimeType: string;
  readonly extension: string;
  render(report: CanonicalSecurityReport): TOutput;
}

/**
 * Complete generated report bundle containing requested formats and export metadata.
 */
export interface GeneratedReportBundle {
  reportId: string;
  generatedAt: string;
  canonical: CanonicalSecurityReport;
  json?: {
    content: CanonicalSecurityReport;
    serialized: string;
    exportMetadata: ReportExportMetadata;
  };
  html?: {
    content: string;
    exportMetadata: ReportExportMetadata;
  };
  pdfReady?: {
    content: PdfReadyDocument;
    exportMetadata: ReportExportMetadata;
  };
  exportMetadata: Partial<Record<ExportFormat, ReportExportMetadata>>;
}
