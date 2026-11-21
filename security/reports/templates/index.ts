import type {
  CanonicalSecurityReport,
  PdfReadyDocument,
  ReportTemplate,
} from "@/types/report-generator.types";
import { escapeHtml, renderSecurityReportHtml } from "./html.template";
import { buildPdfReadyStructure } from "./pdf-structure.template";

export { escapeHtml, renderSecurityReportHtml } from "./html.template";
export { buildPdfReadyStructure } from "./pdf-structure.template";

/**
 * Built-in canonical JSON report template.
 */
export const jsonReportTemplate: ReportTemplate<CanonicalSecurityReport> = {
  format: "json",
  mimeType: "application/json",
  extension: "json",
  render(report: CanonicalSecurityReport): CanonicalSecurityReport {
    return report;
  },
};

/**
 * Built-in self-contained HTML5 report template.
 */
export const htmlReportTemplate: ReportTemplate<string> = {
  format: "html",
  mimeType: "text/html",
  extension: "html",
  render(report: CanonicalSecurityReport): string {
    return renderSecurityReportHtml(report);
  },
};

/**
 * Built-in paginated PDF-Ready AST template.
 */
export const pdfReadyReportTemplate: ReportTemplate<PdfReadyDocument> = {
  format: "pdf",
  mimeType: "application/json",
  extension: "pdf.json",
  render(report: CanonicalSecurityReport): PdfReadyDocument {
    return buildPdfReadyStructure(report);
  },
};

/**
 * Pluggable registry for security report output templates.
 * New formats (such as SARIF, CSV, DOCX, or custom enterprise layouts) can be
 * registered at runtime without modifying the core report generator.
 */
export class ReportTemplateRegistry {
  private readonly templates = new Map<string, ReportTemplate<unknown>>();

  constructor(initialTemplates: readonly ReportTemplate<unknown>[] = []) {
    for (const template of initialTemplates) {
      this.register(template);
    }
  }

  public register<TOutput>(template: ReportTemplate<TOutput>): this {
    const key = template.format.trim().toLowerCase();
    if (!key) {
      throw new Error("Report template format identifier cannot be empty.");
    }
    this.templates.set(key, template as ReportTemplate<unknown>);
    return this;
  }

  public unregister(format: string): boolean {
    return this.templates.delete(format.trim().toLowerCase());
  }

  public has(format: string): boolean {
    return this.templates.has(format.trim().toLowerCase());
  }

  public get<TOutput = unknown>(
    format: string
  ): ReportTemplate<TOutput> | undefined {
    return this.templates.get(format.trim().toLowerCase()) as
      | ReportTemplate<TOutput>
      | undefined;
  }

  public listFormats(): string[] {
    return Array.from(this.templates.keys());
  }

  public listTemplates(): ReportTemplate<unknown>[] {
    return Array.from(this.templates.values());
  }

  public render<TOutput = unknown>(
    format: string,
    report: CanonicalSecurityReport
  ): TOutput {
    const template = this.get<TOutput>(format);
    if (!template) {
      throw new Error(
        `No report template registered for format '${format}'. Registered formats: ${this.listFormats().join(", ")}`
      );
    }
    return template.render(report);
  }
}

/**
 * Default template registry pre-loaded with JSON, HTML, and PDF-Ready templates.
 */
export const defaultReportTemplateRegistry = new ReportTemplateRegistry([
  jsonReportTemplate,
  htmlReportTemplate,
  pdfReadyReportTemplate,
]);
