import { z } from "zod";
import {
  defaultReportGenerator,
  SecurityReportGenerator,
} from "@/security/reports/report-generator";
import type {
  GeneratedReportBundle,
  ReportGeneratorInput,
  ReportOutputFormat,
} from "@/types/report-generator.types";

const severitySchema = z.enum(["critical", "high", "medium", "low", "info"]);

const riskLevelSchema = z.enum([
  "minimal",
  "low",
  "moderate",
  "high",
  "critical",
]);

const vulnerabilityStatusSchema = z.enum([
  "open",
  "acknowledged",
  "fixed",
  "false_positive",
]);

const timelineStatusSchema = z.enum([
  "completed",
  "in_progress",
  "pending",
  "failed",
  "blocked",
  "info",
]);

const developerSchema = z.object({
  name: z.string().trim().min(1, "Developer name is required").max(160),
  email: z.string().trim().email("Invalid developer email").max(255).optional(),
  role: z.string().trim().min(1).max(120).optional(),
});

const securityScoreSchema = z.object({
  score: z.number().finite().min(0).max(1000),
  percentage: z.number().finite().min(0).max(100),
  letterGrade: z.string().trim().min(1).max(4),
  securityLevel: z.string().trim().min(1).max(64).optional(),
});

const threatSummaryPartialSchema = z
  .object({
    totalDetected: z.number().int().min(0).optional(),
    totalFixed: z.number().int().min(0).optional(),
    openIssues: z.number().int().min(0).optional(),
    critical: z.number().int().min(0).optional(),
    high: z.number().int().min(0).optional(),
    medium: z.number().int().min(0).optional(),
    low: z.number().int().min(0).optional(),
    info: z.number().int().min(0).optional(),
    executiveOverview: z.string().trim().max(4000).optional(),
  })
  .optional();

const vulnerabilityItemSchema = z.object({
  id: z.string().trim().min(1).max(128).optional(),
  ruleId: z.string().trim().min(1, "ruleId is required").max(128),
  title: z.string().trim().min(1, "Vulnerability title is required").max(255),
  description: z.string().trim().min(1, "Vulnerability description is required").max(4000),
  severity: severitySchema,
  category: z.string().trim().min(1).max(64).optional(),
  cweId: z.string().trim().min(1).max(32).optional(),
  owaspCategory: z.string().trim().min(1).max(128).optional(),
  status: vulnerabilityStatusSchema.optional(),
  fileName: z.string().trim().min(1).max(255).optional(),
  line: z.number().int().min(1).optional(),
  column: z.number().int().min(0).optional(),
  snippet: z.string().max(8000).optional(),
  explanation: z.string().max(4000).optional(),
  remediationSummary: z.string().max(2000).optional(),
  confidence: z.number().min(0).max(1).optional(),
});

const fixAppliedItemSchema = z.object({
  id: z.string().trim().min(1).max(128).optional(),
  vulnerabilityId: z.string().trim().min(1).max(128).optional(),
  ruleId: z.string().trim().min(1).max(128).optional(),
  title: z.string().trim().min(1, "Fix title is required").max(255),
  summary: z.string().trim().min(1, "Fix summary is required").max(2000),
  fileName: z.string().trim().min(1).max(255).optional(),
  line: z.number().int().min(1).optional(),
  riskReduction: z.number().finite().min(0).max(100),
  appliedAt: z.string().trim().min(1).max(64).optional(),
  appliedBy: z.string().trim().min(1).max(160).optional(),
  verified: z.boolean().optional(),
});

const recommendationObjectSchema = z.object({
  title: z.string().trim().min(1).max(255),
  description: z.string().trim().min(1).max(2000),
  priority: z.enum(["immediate", "short-term", "long-term"]),
  category: z.string().trim().min(1).max(64).optional(),
  impact: z.enum(["high", "medium", "low"]).optional(),
});

const recommendationInputSchema = z.union([
  z.string().trim().min(1).max(2000),
  recommendationObjectSchema,
]);

const recommendationsSchema = z
  .object({
    immediate: z.array(recommendationInputSchema).max(50).optional(),
    shortTerm: z.array(recommendationInputSchema).max(50).optional(),
    longTerm: z.array(recommendationInputSchema).max(50).optional(),
  })
  .optional();

const timelineEventSchema = z.object({
  timestamp: z.string().trim().min(1, "Timeline timestamp is required").max(64),
  formattedTime: z.string().trim().min(1).max(128).optional(),
  action: z.string().trim().min(1, "Timeline action is required").max(500),
  severity: severitySchema,
  status: timelineStatusSchema,
  actor: z.string().trim().min(1).max(160).optional(),
  details: z.string().trim().max(2000).optional(),
});

const sourceMetadataSchema = z
  .object({
    scanId: z.string().trim().min(1).max(128).optional(),
    fileName: z.string().trim().min(1).max(255).optional(),
    language: z.string().trim().min(1).max(64).optional(),
    branch: z.string().trim().min(1).max(128).optional(),
    commitSha: z.string().trim().min(1).max(64).optional(),
    environment: z.string().trim().min(1).max(64).optional(),
  })
  .optional();

export const reportOutputFormatSchema = z.enum(["json", "html", "pdf", "all"]);

export const reportGeneratorInputSchema = z.object({
  reportId: z.string().trim().min(1).max(128).optional(),
  projectName: z.string().trim().min(1, "projectName is required").max(200),
  developer: developerSchema,
  date: z.union([z.string().trim().min(1).max(64), z.date()]).optional(),
  securityScore: securityScoreSchema,
  riskLevel: riskLevelSchema.optional(),
  threatSummary: threatSummaryPartialSchema,
  vulnerabilities: z.array(vulnerabilityItemSchema).max(500),
  fixesApplied: z.array(fixAppliedItemSchema).max(500).optional(),
  recommendations: recommendationsSchema,
  timeline: z.array(timelineEventSchema).max(500).optional(),
  metadata: sourceMetadataSchema,
});

export const reportGeneratorRequestSchema = reportGeneratorInputSchema.extend({
  format: reportOutputFormatSchema.default("all"),
  download: z.boolean().default(false),
});

export type ReportGeneratorRequest = z.infer<typeof reportGeneratorRequestSchema>;

export interface ReportGenerationResult {
  format: ReportOutputFormat;
  download: boolean;
  bundle: GeneratedReportBundle;
}

/**
 * Service layer coordinating Zod validation and modular report generation
 * across JSON, HTML, and PDF-Ready output formats.
 */
export class ReportGeneratorService {
  private readonly generator: SecurityReportGenerator;

  constructor(generator: SecurityReportGenerator = defaultReportGenerator) {
    this.generator = generator;
  }

  /**
   * Validates an unknown request payload with Zod and generates the requested
   * report bundle.
   */
  public generateFromRequest(rawInput: unknown): ReportGenerationResult {
    const parsed = reportGeneratorRequestSchema.parse(rawInput);
    const { format, download, ...reportInput } = parsed;

    const bundle = this.generator.generate(reportInput, format);

    return {
      format,
      download,
      bundle,
    };
  }

  /**
   * Generates a report bundle from already-typed input (still validated for safety).
   */
  public generateBundle(
    input: ReportGeneratorInput,
    format: ReportOutputFormat = "all"
  ): GeneratedReportBundle {
    const validated = reportGeneratorInputSchema.parse(input);
    return this.generator.generate(validated, format);
  }
}

export const reportGeneratorService = new ReportGeneratorService();
