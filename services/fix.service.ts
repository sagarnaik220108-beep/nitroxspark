import { z } from "zod";
import {
  defaultSecureFixEngine,
  SecureFixEngine,
} from "@/security/fixes";
import type {
  BatchSecureFixResult,
  FixerMetadata,
  SecureFixResult,
} from "@/types/fix.types";
import {
  parseOrThrow,
  severitySchema,
  supportedLanguageSchema,
} from "@/utils/validators";

const MAX_CODE_BYTES = Number(process.env.MAX_CODE_SIZE_BYTES ?? 262_144);

const sourceCodeSchema = z
  .string()
  .min(1, "originalCode cannot be empty")
  .refine(
    (val) => new TextEncoder().encode(val).length <= MAX_CODE_BYTES,
    `originalCode exceeds maximum allowed size (${MAX_CODE_BYTES} bytes)`
  );

export const fixVulnerabilityInputSchema = z.object({
  ruleId: z.string().trim().min(1, "vulnerability.ruleId is required"),
  name: z.string().trim().min(1).optional(),
  title: z.string().trim().min(1).optional(),
  category: z.string().trim().min(1, "vulnerability.category is required"),
  severity: severitySchema,
  fileLine: z.number().int().min(1).optional(),
  line: z.number().int().min(1).optional(),
  location: z
    .object({
      line: z.number().int().min(1),
      endLine: z.number().int().min(1).optional(),
    })
    .optional(),
  matchedText: z.string().optional(),
  language: supportedLanguageSchema.optional(),
  cweId: z.string().trim().optional(),
  description: z.string().optional(),
});

export const generateFixRequestSchema = z.object({
  originalCode: sourceCodeSchema,
  vulnerability: fixVulnerabilityInputSchema,
});

export const generateBatchFixRequestSchema = z.object({
  originalCode: sourceCodeSchema,
  vulnerabilities: z
    .array(fixVulnerabilityInputSchema)
    .min(1, "At least one vulnerability is required"),
});

export const fixRequestSchema = z.union([
  generateFixRequestSchema,
  generateBatchFixRequestSchema,
]);

export type GenerateFixRequest = z.infer<typeof generateFixRequestSchema>;
export type GenerateBatchFixRequest = z.infer<
  typeof generateBatchFixRequestSchema
>;

/**
 * Application service for the Sentinel AI Secure Fix Engine.
 * Validates incoming payloads with Zod and delegates transformations to SecureFixEngine.
 */
export class FixService {
  constructor(
    private readonly engine: SecureFixEngine = defaultSecureFixEngine
  ) {}

  /**
   * Validates and generates a secure fix for a single vulnerability.
   */
  public generateFix(rawInput: unknown): SecureFixResult {
    const validated = parseOrThrow(generateFixRequestSchema, rawInput);
    return this.engine.generateFix(validated);
  }

  /**
   * Validates and generates a combined secure fix for multiple vulnerabilities.
   */
  public generateBatchFix(rawInput: unknown): BatchSecureFixResult {
    const validated = parseOrThrow(generateBatchFixRequestSchema, rawInput);
    return this.engine.generateBatchFix(
      validated.originalCode,
      validated.vulnerabilities
    );
  }

  /**
   * Accepts either `{ originalCode, vulnerability }` or `{ originalCode, vulnerabilities }`.
   */
  public processFixRequest(
    rawInput: unknown
  ): SecureFixResult | BatchSecureFixResult {
    const validated = parseOrThrow(fixRequestSchema, rawInput);
    if ("vulnerabilities" in validated) {
      return this.engine.generateBatchFix(
        validated.originalCode,
        validated.vulnerabilities
      );
    }
    return this.engine.generateFix(validated);
  }

  /**
   * Lists metadata for all registered fixers.
   */
  public listAvailableFixers(): FixerMetadata[] {
    return this.engine.listFixers();
  }
}

export const fixService = new FixService(defaultSecureFixEngine);
