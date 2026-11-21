import { z } from "zod";
import {
  CATEGORY_FALLBACK_TEMPLATES,
  CORE_EXPLANATION_TEMPLATES,
  GENERIC_FALLBACK_TEMPLATE,
} from "@/security/explanations/templates";
import type {
  BatchExplanationResult,
  BeginnerFriendlyExplanation,
  ExplanationOptions,
  ExplanationSource,
  ExplanationTemplate,
  ExplanationTemplateMetadata,
  VulnerabilityExplanationInput,
} from "@/types/explanation.types";
import type { Severity, SupportedLanguage } from "@/types/security.types";
import { ValidationError } from "@/utils/errors";
import { severitySchema } from "@/utils/validators";

const SUPPORTED_LANGUAGES: ReadonlySet<SupportedLanguage> = new Set([
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

const LANGUAGE_ALIASES: Record<string, SupportedLanguage> = {
  ts: "typescript",
  tsx: "typescript",
  typescript: "typescript",
  js: "javascript",
  jsx: "javascript",
  mjs: "javascript",
  cjs: "javascript",
  javascript: "javascript",
  py: "python",
  python: "python",
  sql: "sql",
  postgres: "sql",
  mysql: "sql",
  java: "java",
  go: "go",
  golang: "go",
  php: "php",
  rb: "ruby",
  ruby: "ruby",
  cs: "csharp",
  "c#": "csharp",
  csharp: "csharp",
};

/**
 * Zod schema validating single vulnerability explanation requests.
 */
export const vulnerabilityExplanationInputSchema = z
  .object({
    ruleId: z.string().trim().min(1).max(120).optional(),
    name: z.string().trim().min(1).max(200).optional(),
    title: z.string().trim().min(1).max(200).optional(),
    severity: z.preprocess(
      (val) => (typeof val === "string" ? val.toLowerCase().trim() : val),
      severitySchema.optional()
    ),
    category: z.string().trim().min(1).max(100).optional(),
    description: z.string().trim().min(1).max(2000).optional(),
    snippet: z.string().max(4000).optional(),
    codeSnippet: z.string().max(4000).optional(),
    fileLine: z.coerce.number().int().positive().optional(),
    line: z.coerce.number().int().positive().optional(),
    fileName: z.string().trim().min(1).max(255).optional(),
    language: z.string().trim().min(1).max(50).optional(),
    cweId: z.string().trim().min(1).max(40).optional(),
    owaspCategory: z.string().trim().min(1).max(150).optional(),
  })
  .refine(
    (data) =>
      Boolean(
        data.ruleId ||
          data.name ||
          data.title ||
          data.category ||
          data.description
      ),
    {
      message:
        "Provide at least one of: ruleId, name, title, category, or description",
    }
  );

/**
 * Zod schema validating batch explanation requests.
 */
export const batchExplanationInputSchema = z
  .array(vulnerabilityExplanationInputSchema)
  .min(1, "At least one vulnerability is required")
  .max(100, "A maximum of 100 vulnerabilities can be explained per request");

const aiEnhancedFieldsSchema = z.object({
  whatItIs: z.string().trim().min(20),
  whyItHappens: z.string().trim().min(20),
  howHackersExploitIt: z.string().trim().min(20),
  realWorldAnalogy: z.string().trim().min(15),
  impact: z.string().trim().min(15),
  bestPractice: z.string().trim().min(20),
  secureVersion: z.string().trim().min(10),
});

type ValidatedInput = z.infer<typeof vulnerabilityExplanationInputSchema>;
type SupportedAIProvider = "openai" | "gemini" | "anthropic";

function validateOrThrow<T>(
  schema: z.ZodType<T, z.ZodTypeDef, unknown>,
  input: unknown
): T {
  const result = schema.safeParse(input);
  if (!result.success) {
    throw new ValidationError(
      "Vulnerability explanation input validation failed",
      result.error.flatten().fieldErrors
    );
  }
  return result.data;
}

function normalizeLanguage(raw?: string): SupportedLanguage | undefined {
  if (!raw) return undefined;
  const cleaned = raw.toLowerCase().trim();
  const aliased = LANGUAGE_ALIASES[cleaned];
  if (aliased) return aliased;
  if (SUPPORTED_LANGUAGES.has(cleaned as SupportedLanguage)) {
    return cleaned as SupportedLanguage;
  }
  return "unknown";
}

function sanitizeSnippetForContext(snippet: string): string {
  const singleLine = snippet.replace(/\s+/g, " ").trim();
  // Redact obvious high-entropy token literals so explanations don't echo raw secrets
  const redacted = singleLine.replace(
    /\b(AKIA[0-9A-Z]{16}|sk-(?:live|test|proj)?-?[a-zA-Z0-9_-]{16,}|gh[pousr]_[a-zA-Z0-9]{16,}|AIza[0-9A-Za-z_-]{20,})\b/g,
    (match) => `${match.slice(0, 6)}...[REDACTED]`
  );
  return redacted.length > 140 ? `${redacted.slice(0, 137)}...` : redacted;
}

function extractJsonObject(rawText: string): unknown {
  const trimmed = rawText.trim();
  const fencedMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fencedMatch?.[1]?.trim() ?? trimmed;
  const firstBrace = candidate.indexOf("{");
  const lastBrace = candidate.lastIndexOf("}");
  if (firstBrace === -1 || lastBrace === -1 || lastBrace <= firstBrace) {
    throw new Error("No JSON object found in AI response");
  }
  return JSON.parse(candidate.slice(firstBrace, lastBrace + 1));
}

/**
 * Reusable, beginner-friendly AI Explanation Service for Sentinel AI.
 *
 * Works deterministically out-of-the-box with curated templates for all 12 core
 * Sentinel AI vulnerability categories, plus category and generic fallbacks.
 * Optionally enhances explanations with an LLM when `AI_PROVIDER` and
 * `AI_API_KEY` are configured in the server environment.
 */
export class ExplanationService {
  private readonly templates: ExplanationTemplate[];

  constructor(initialTemplates: readonly ExplanationTemplate[] = CORE_EXPLANATION_TEMPLATES) {
    this.templates = [...initialTemplates];
  }

  /**
   * Registers an additional explanation template at runtime for custom rules.
   */
  public registerTemplate(template: ExplanationTemplate): void {
    const existingIndex = this.templates.findIndex((t) => t.id === template.id);
    if (existingIndex >= 0) {
      this.templates[existingIndex] = template;
    } else {
      this.templates.unshift(template);
    }
  }

  /**
   * Lists metadata for all supported primary explanation templates.
   */
  public listSupportedTemplates(): ExplanationTemplateMetadata[] {
    return this.templates.map((template) => {
      const extraLanguages = template.secureVersionsByLanguage
        ? (Object.keys(template.secureVersionsByLanguage) as SupportedLanguage[])
        : [];
      const supportedLanguages: SupportedLanguage[] = Array.from(
        new Set<SupportedLanguage>(["typescript", "javascript", ...extraLanguages])
      );

      return {
        id: template.id,
        name: template.name,
        category: template.category,
        defaultSeverity: template.defaultSeverity,
        ruleIds: template.ruleIds,
        keywords: template.keywords,
        ...(template.defaultCweId ? { defaultCweId: template.defaultCweId } : {}),
        ...(template.defaultOwaspCategory
          ? { defaultOwaspCategory: template.defaultOwaspCategory }
          : {}),
        supportedLanguages,
      };
    });
  }

  /**
   * Generates a beginner-friendly structured JSON explanation for a single
   * detected vulnerability.
   */
  public async explain(
    input: VulnerabilityExplanationInput,
    options: ExplanationOptions = {}
  ): Promise<BeginnerFriendlyExplanation> {
    const validated = validateOrThrow(
      vulnerabilityExplanationInputSchema,
      input
    );
    const template = this.resolveTemplate(validated);
    const baseExplanation = this.buildContextualExplanation(validated, template);

    if (options.useAI !== false) {
      const enhanced = await this.tryEnhanceWithAI(validated, baseExplanation);
      if (enhanced) {
        return enhanced;
      }
    }

    return baseExplanation;
  }

  /**
   * Generates beginner-friendly explanations for an array of detected
   * vulnerabilities and returns aggregated severity/source statistics.
   */
  public async explainMany(
    inputs: VulnerabilityExplanationInput[],
    options: ExplanationOptions = {}
  ): Promise<BatchExplanationResult> {
    const validatedInputs = validateOrThrow(
      batchExplanationInputSchema,
      inputs
    );

    const explanations = await Promise.all(
      validatedInputs.map((item) => this.explain(item, options))
    );

    const severitySummary: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    const sourceSummary: Record<ExplanationSource, number> = {
      template: 0,
      "ai-enhanced": 0,
    };

    for (const explanation of explanations) {
      severitySummary[explanation.severity] += 1;
      sourceSummary[explanation.source] += 1;
    }

    return {
      total: explanations.length,
      explanations,
      severitySummary,
      sourceSummary,
    };
  }

  /**
   * Resolves the best-matching template using a 4-tier strategy:
   * 1. Exact `ruleId` match (case-insensitive)
   * 2. Weighted keyword match against `name`, `title`, `description`, `cweId`, `ruleId`
   * 3. Category-based match (direct primary template or category fallback)
   * 4. Generic fallback template
   */
  private resolveTemplate(input: ValidatedInput): ExplanationTemplate {
    const allSearchableTemplates: ExplanationTemplate[] = [
      ...this.templates,
      ...Object.values(CATEGORY_FALLBACK_TEMPLATES),
    ];

    // 1. Exact ruleId match
    if (input.ruleId) {
      const normalizedRuleId = input.ruleId.toLowerCase();
      const exactMatch = allSearchableTemplates.find((template) =>
        template.ruleIds.some((id) => id.toLowerCase() === normalizedRuleId)
      );
      if (exactMatch) {
        return exactMatch;
      }
    }

    // 2. Weighted keyword match
    const primaryText = [input.name, input.title, input.ruleId, input.cweId]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    const secondaryText = [input.description, input.snippet, input.codeSnippet]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();

    let bestTemplate: ExplanationTemplate | null = null;
    let bestScore = 0;

    for (const template of allSearchableTemplates) {
      let score = 0;
      for (const keyword of template.keywords) {
        const kw = keyword.toLowerCase();
        // Multi-word / specific keywords receive higher weight
        const specificityBonus = Math.min(kw.length, 24);
        if (primaryText.includes(kw)) {
          score += 100 + specificityBonus * 2;
        } else if (secondaryText.includes(kw)) {
          score += 35 + specificityBonus;
        }
      }

      // Slight preference for curated primary templates over fallbacks on ties
      if (score > 0 && !template.isFallback) {
        score += 15;
      }

      if (score > bestScore) {
        bestScore = score;
        bestTemplate = template;
      }
    }

    if (bestTemplate && bestScore > 0) {
      return bestTemplate;
    }

    // 3. Category-based resolution
    if (input.category) {
      const normalizedCategory = input.category.toLowerCase().trim();

      const categoryFallback = CATEGORY_FALLBACK_TEMPLATES[normalizedCategory];
      if (categoryFallback) {
        return categoryFallback;
      }

      // Map core categories directly to their primary template when no separate fallback exists
      const categoryToPrimary: Record<string, string> = {
        secrets: "hardcoded-api-keys",
        xss: "cross-site-scripting",
        authentication: "weak-authentication",
        authorization: "missing-authorization",
        dependencies: "outdated-packages",
        "supply-chain": "outdated-packages",
        database: "open-database-connection",
        environment: "exposed-environment-variables",
      };

      const mappedId = categoryToPrimary[normalizedCategory];
      if (mappedId) {
        const matchedPrimary = this.templates.find((t) => t.id === mappedId);
        if (matchedPrimary) {
          return matchedPrimary;
        }
      }
    }

    // 4. Generic fallback
    return GENERIC_FALLBACK_TEMPLATE;
  }

  /**
   * Builds a contextualized beginner-friendly explanation from the matched template
   * and the specific vulnerability metadata (line number, language, snippet).
   */
  private buildContextualExplanation(
    input: ValidatedInput,
    template: ExplanationTemplate
  ): BeginnerFriendlyExplanation {
    const language = normalizeLanguage(input.language);
    const fileLine = input.fileLine ?? input.line;
    const rawSnippet = input.snippet ?? input.codeSnippet;
    const vulnerabilityName = input.name ?? input.title ?? template.name;
    const severity: Severity = input.severity ?? template.defaultSeverity;
    const category = input.category ?? template.category;
    const cweId = input.cweId ?? template.defaultCweId;
    const owaspCategory = input.owaspCategory ?? template.defaultOwaspCategory;

    const secureVersion =
      (language && template.secureVersionsByLanguage?.[language]) ??
      template.secureVersion;

    // For fallback templates, incorporate the caller's description so the explanation stays specific
    const whatItIs =
      template.isFallback && input.description
        ? `${template.whatItIs} Specifically in your code: ${input.description}`
        : template.whatItIs;

    const contextParts: string[] = [];
    if (fileLine !== undefined && input.fileName) {
      contextParts.push(`Found in ${input.fileName} at line ${fileLine}`);
    } else if (fileLine !== undefined) {
      contextParts.push(`Found at line ${fileLine}`);
    } else if (input.fileName) {
      contextParts.push(`Found in ${input.fileName}`);
    }

    if (language && language !== "unknown") {
      contextParts.push(`Language: ${language}`);
    }

    if (rawSnippet && rawSnippet.trim().length > 0) {
      contextParts.push(
        `Flagged pattern: \`${sanitizeSnippetForContext(rawSnippet)}\``
      );
    }

    const contextNote =
      contextParts.length > 0 ? `${contextParts.join(" · ")}.` : undefined;

    return {
      whatItIs,
      whyItHappens: template.whyItHappens,
      howHackersExploitIt: template.howHackersExploitIt,
      realWorldAnalogy: template.realWorldAnalogy,
      impact: template.impact,
      bestPractice: template.bestPractice,
      secureVersion,
      templateId: template.id,
      vulnerabilityName,
      ...(input.ruleId ? { ruleId: input.ruleId } : {}),
      severity,
      category,
      ...(language ? { language } : {}),
      ...(fileLine !== undefined ? { fileLine } : {}),
      ...(cweId ? { cweId } : {}),
      ...(owaspCategory ? { owaspCategory } : {}),
      source: "template",
      ...(contextNote ? { contextNote } : {}),
    };
  }

  /**
   * Optional LLM enhancement using `AI_PROVIDER` (`openai` | `gemini` | `anthropic`)
   * and `AI_API_KEY`. Always falls back gracefully to the deterministic template
   * if unconfigured, rate-limited, timed out, or malformed.
   */
  private async tryEnhanceWithAI(
    input: ValidatedInput,
    fallback: BeginnerFriendlyExplanation
  ): Promise<BeginnerFriendlyExplanation | null> {
    const provider = process.env.AI_PROVIDER?.toLowerCase().trim();
    const apiKey = process.env.AI_API_KEY?.trim();

    if (
      !apiKey ||
      (provider !== "openai" &&
        provider !== "gemini" &&
        provider !== "anthropic")
    ) {
      return null;
    }

    const prompt = this.buildEnhancementPrompt(input, fallback);

    try {
      const rawResponse = await this.callAIProvider(provider, apiKey, prompt);
      const parsedJson = extractJsonObject(rawResponse);
      const validated = aiEnhancedFieldsSchema.safeParse(parsedJson);

      if (!validated.success) {
        return null;
      }

      return {
        ...fallback,
        ...validated.data,
        source: "ai-enhanced",
      };
    } catch (error) {
      console.warn(
        `[Sentinel AI] Optional AI explanation enhancement (${provider}) fell back to curated template:`,
        error instanceof Error ? error.message : "Unknown error"
      );
      return null;
    }
  }

  private buildEnhancementPrompt(
    input: ValidatedInput,
    baseline: BeginnerFriendlyExplanation
  ): string {
    const rawSnippet = input.snippet ?? input.codeSnippet;
    const safeSnippet = rawSnippet
      ? sanitizeSnippetForContext(rawSnippet)
      : "Not provided";

    return [
      "You are Sentinel AI, a friendly cybersecurity mentor helping beginners understand and fix code vulnerabilities.",
      "Rewrite and tailor the vulnerability explanation below to the specific code context while keeping it warm, jargon-free, strictly defensive/educational, and accurate.",
      "Return ONLY a valid JSON object with these exact string keys:",
      '  "whatItIs", "whyItHappens", "howHackersExploitIt", "realWorldAnalogy", "impact", "bestPractice", "secureVersion"',
      "",
      "Vulnerability context:",
      `- Name: ${baseline.vulnerabilityName}`,
      `- Rule ID: ${baseline.ruleId ?? "N/A"}`,
      `- Severity: ${baseline.severity}`,
      `- Category: ${baseline.category}`,
      `- Language: ${baseline.language ?? "typescript"}`,
      `- Line: ${baseline.fileLine ?? "N/A"}`,
      `- CWE: ${baseline.cweId ?? "N/A"}`,
      `- Code Snippet: ${safeSnippet}`,
      "",
      "Baseline curated explanation to tailor:",
      JSON.stringify({
        whatItIs: baseline.whatItIs,
        whyItHappens: baseline.whyItHappens,
        howHackersExploitIt: baseline.howHackersExploitIt,
        realWorldAnalogy: baseline.realWorldAnalogy,
        impact: baseline.impact,
        bestPractice: baseline.bestPractice,
        secureVersion: baseline.secureVersion,
      }),
    ].join("\n");
  }

  private async callAIProvider(
    provider: SupportedAIProvider,
    apiKey: string,
    prompt: string
  ): Promise<string> {
    const timeoutSignal = AbortSignal.timeout(10_000);

    if (provider === "openai") {
      const model = process.env.AI_MODEL?.trim() || "gpt-4o-mini";
      const response = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model,
          temperature: 0.2,
          response_format: { type: "json_object" },
          messages: [
            {
              role: "system",
              content:
                "You output only strict JSON objects explaining security vulnerabilities in beginner-friendly language.",
            },
            { role: "user", content: prompt },
          ],
        }),
        signal: timeoutSignal,
      });

      if (!response.ok) {
        throw new Error(`OpenAI API returned HTTP ${response.status}`);
      }

      const data = (await response.json()) as {
        choices?: Array<{ message?: { content?: string } }>;
      };
      const content = data.choices?.[0]?.message?.content;
      if (!content) {
        throw new Error("OpenAI API returned an empty response");
      }
      return content;
    }

    if (provider === "gemini") {
      const model = process.env.AI_MODEL?.trim() || "gemini-2.0-flash";
      const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;
      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-goog-api-key": apiKey,
        },
        body: JSON.stringify({
          contents: [{ role: "user", parts: [{ text: prompt }] }],
          generationConfig: {
            temperature: 0.2,
            responseMimeType: "application/json",
          },
        }),
        signal: timeoutSignal,
      });

      if (!response.ok) {
        throw new Error(`Gemini API returned HTTP ${response.status}`);
      }

      const data = (await response.json()) as {
        candidates?: Array<{
          content?: { parts?: Array<{ text?: string }> };
        }>;
      };
      const content = data.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!content) {
        throw new Error("Gemini API returned an empty response");
      }
      return content;
    }

    // Anthropic
    const model = process.env.AI_MODEL?.trim() || "claude-3-5-haiku-latest";
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model,
        max_tokens: 1500,
        temperature: 0.2,
        messages: [{ role: "user", content: prompt }],
      }),
      signal: timeoutSignal,
    });

    if (!response.ok) {
      throw new Error(`Anthropic API returned HTTP ${response.status}`);
    }

    const data = (await response.json()) as {
      content?: Array<{ type?: string; text?: string }>;
    };
    const textBlock = data.content?.find((block) => block.type === "text");
    if (!textBlock?.text) {
      throw new Error("Anthropic API returned an empty response");
    }
    return textBlock.text;
  }
}

export const explanationService = new ExplanationService();
