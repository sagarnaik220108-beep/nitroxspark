import { z } from "zod";
import { ValidationError } from "./errors";

const MAX_CODE_BYTES = Number(process.env.MAX_CODE_SIZE_BYTES ?? 262_144);

export const supportedLanguageSchema = z.enum([
  "typescript",
  "javascript",
  "python",
  "sql",
  "java",
  "go",
  "php",
  "ruby",
  "csharp",
  "unknown",
]);

export const severitySchema = z.enum([
  "critical",
  "high",
  "medium",
  "low",
  "info",
]);

export const vulnerabilityCategorySchema = z.enum([
  "injection",
  "xss",
  "secrets",
  "authentication",
  "authorization",
  "ssrf",
  "path-traversal",
  "cryptography",
  "misconfiguration",
  "deserialization",
  "other",
]);

export const vulnerabilityStatusSchema = z.enum([
  "open",
  "acknowledged",
  "fixed",
  "false_positive",
]);

export const createScanSchema = z.object({
  projectName: z
    .string()
    .trim()
    .min(1, "Project name is required")
    .max(120, "Project name must be 120 characters or fewer")
    .default("Untitled Project"),
  fileName: z
    .string()
    .trim()
    .min(1, "File name is required")
    .max(255, "File name must be 255 characters or fewer")
    .default("snippet.ts"),
  language: supportedLanguageSchema.optional(),
  code: z.string().min(1, "Source code cannot be empty"),
  aiModelSource: z.string().trim().max(100).optional(),
  includeCustomRules: z.boolean().default(true),
  enabledRuleIds: z.array(z.string().trim().min(1)).optional(),
  disabledRuleIds: z.array(z.string().trim().min(1)).optional(),
});

export type CreateScanInput = z.infer<typeof createScanSchema>;

export const simulateAttackSchema = z.object({
  scanId: z.string().uuid("Invalid scanId UUID"),
  vulnerabilityId: z.string().uuid("Invalid vulnerabilityId UUID").optional(),
});

export type SimulateAttackInput = z.infer<typeof simulateAttackSchema>;

export const generateReportSchema = z.object({
  scanId: z.string().uuid("Invalid scanId UUID"),
  title: z.string().trim().min(1).max(200).optional(),
  format: z.enum(["json", "markdown"]).default("json"),
  includeSimulations: z.boolean().default(true),
});

export type GenerateReportInput = z.infer<typeof generateReportSchema>;

export const updateVulnerabilityStatusSchema = z.object({
  status: vulnerabilityStatusSchema,
});

export type UpdateVulnerabilityStatusInput = z.infer<
  typeof updateVulnerabilityStatusSchema
>;

export const createCustomRuleSchema = z.object({
  ruleKey: z
    .string()
    .trim()
    .min(3)
    .max(64)
    .regex(
      /^[A-Z0-9_-]+$/,
      "ruleKey must contain only uppercase letters, digits, underscores, or hyphens"
    ),
  name: z.string().trim().min(3).max(120),
  description: z.string().trim().min(10).max(500),
  explanation: z.string().trim().min(10).max(2000),
  severity: severitySchema,
  category: vulnerabilityCategorySchema,
  cweId: z
    .string()
    .trim()
    .regex(/^CWE-\d+$/, "cweId must match format CWE-XXX"),
  owaspCategory: z.string().trim().min(3).max(120),
  languages: z.array(supportedLanguageSchema).min(1),
  pattern: z
    .string()
    .min(2)
    .max(500)
    .refine((pattern) => {
      try {
        new RegExp(pattern, "g");
        return true;
      } catch {
        return false;
      }
    }, "Pattern must be a valid JavaScript regular expression"),
  patternFlags: z
    .string()
    .regex(/^[gimsuy]*$/, "Invalid RegExp flags")
    .default("gi"),
  remediation: z.object({
    summary: z.string().trim().min(5).max(300),
    explanation: z.string().trim().min(10).max(2000),
    secureCodeExample: z.string().min(5).max(4000),
    references: z.array(z.string().url()).default([]),
  }),
  enabled: z.boolean().default(true),
});

export type CreateCustomRuleInput = z.infer<typeof createCustomRuleSchema>;

export const paginationQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
});

export type PaginationQuery = z.infer<typeof paginationQuerySchema>;

export const uuidParamSchema = z.string().uuid("Invalid UUID parameter");

/**
 * Parses and validates input against a Zod schema, throwing a typed ValidationError on failure.
 */
export function parseOrThrow<TOutput>(
  schema: z.ZodType<TOutput, z.ZodTypeDef, unknown>,
  input: unknown
): TOutput {
  const result = schema.safeParse(input);
  if (!result.success) {
    throw new ValidationError(
      "Validation failed",
      result.error.flatten().fieldErrors
    );
  }
  return result.data;
}
