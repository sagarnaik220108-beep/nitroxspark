import { execFile } from "node:child_process";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { StructuredVulnerability } from "@/security/analyzer";
import type {
  Severity,
  SupportedLanguage,
  VulnerabilityCategory,
} from "@/types/security.types";
import type {
  SemgrepCliMetadata,
  SemgrepCliOutput,
  SemgrepCliResult,
  SemgrepRuleset,
  SemgrepScanOptions,
  SemgrepScanResult,
} from "@/types/semgrep.types";
import { detectLanguage, extractCodeSnippet } from "@/utils/code.utils";
import { compareSeverity } from "@/utils/scoring.utils";
import { runBuiltinSemgrepRules } from "./semgrep-rules";

const CLI_CACHE_TTL_MS = 60_000;
const CLI_VERSION_TIMEOUT_MS = 3_000;
const CLI_SCAN_TIMEOUT_MS = 15_000;
const CLI_MAX_BUFFER_BYTES = 5 * 1024 * 1024;

const LANGUAGE_EXTENSION_MAP: Record<SupportedLanguage, string> = {
  typescript: ".ts",
  javascript: ".js",
  python: ".py",
  sql: ".sql",
  java: ".java",
  go: ".go",
  php: ".php",
  ruby: ".rb",
  csharp: ".cs",
  unknown: ".txt",
};

interface CliAvailabilityCache {
  cliAvailable: boolean;
  cliVersion: string | null;
  checkedAt: number;
}

interface ExecFileOutput {
  stdout: string;
  stderr: string;
}

function runExecFile(
  file: string,
  args: readonly string[],
  timeout: number
): Promise<ExecFileOutput> {
  return new Promise((resolve, reject) => {
    execFile(
      file,
      [...args],
      {
        shell: false,
        timeout,
        maxBuffer: CLI_MAX_BUFFER_BYTES,
        windowsHide: true,
      },
      (error, stdout, stderr) => {
        if (error) {
          const enriched = error as Error & {
            stdout?: string;
            stderr?: string;
          };
          enriched.stdout = stdout;
          enriched.stderr = stderr;
          reject(enriched);
          return;
        }
        resolve({ stdout, stderr });
      }
    );
  });
}

function sanitizeTempFileName(
  fileName: string | undefined,
  language: SupportedLanguage
): string {
  const defaultExt = LANGUAGE_EXTENSION_MAP[language];
  if (!fileName) {
    return `target${defaultExt}`;
  }

  const base = path.basename(fileName).replace(/[^a-zA-Z0-9._-]/g, "_");
  if (!base || base === "." || base === "..") {
    return `target${defaultExt}`;
  }

  if (!path.extname(base)) {
    return `${base}${defaultExt}`;
  }

  return base;
}

function firstStringValue(value: string | string[] | undefined): string | null {
  if (typeof value === "string" && value.trim().length > 0) {
    return value.trim();
  }
  if (Array.isArray(value)) {
    const first = value[0];
    if (typeof first === "string" && first.trim().length > 0) {
      return first.trim();
    }
  }
  return null;
}

function extractCweId(metadata: SemgrepCliMetadata | undefined): string {
  const raw = firstStringValue(metadata?.cwe);
  if (!raw) {
    return "CWE-20";
  }
  const match = raw.match(/CWE-\d+/i);
  return match ? match[0].toUpperCase() : raw;
}

function extractOwaspCategory(metadata: SemgrepCliMetadata | undefined): string {
  const raw = firstStringValue(metadata?.owasp);
  return raw ?? "A05:2021 - Security Misconfiguration";
}

function inferCategory(
  checkId: string,
  metadata: SemgrepCliMetadata | undefined
): VulnerabilityCategory {
  const haystack = [
    checkId,
    metadata?.category ?? "",
    ...(metadata?.vulnerability_class ?? []),
    firstStringValue(metadata?.cwe) ?? "",
  ]
    .join(" ")
    .toLowerCase();

  if (
    haystack.includes("secret") ||
    haystack.includes("api-key") ||
    haystack.includes("private-key") ||
    haystack.includes("credential") ||
    haystack.includes("cwe-798")
  ) {
    return "secrets";
  }
  if (haystack.includes("xss") || haystack.includes("cwe-79")) {
    return "xss";
  }
  if (
    haystack.includes("sqli") ||
    haystack.includes("sql-injection") ||
    haystack.includes("command-injection") ||
    haystack.includes("child-process") ||
    haystack.includes("subprocess") ||
    haystack.includes("eval") ||
    haystack.includes("prototype-pollution") ||
    haystack.includes("injection") ||
    haystack.includes("cwe-89") ||
    haystack.includes("cwe-78")
  ) {
    return "injection";
  }
  if (haystack.includes("ssrf") || haystack.includes("cwe-918")) {
    return "ssrf";
  }
  if (
    haystack.includes("path-traversal") ||
    haystack.includes("traversal") ||
    haystack.includes("cwe-22")
  ) {
    return "path-traversal";
  }
  if (
    haystack.includes("deserializ") ||
    haystack.includes("pickle") ||
    haystack.includes("cwe-502")
  ) {
    return "deserialization";
  }
  if (
    haystack.includes("jwt") ||
    haystack.includes("auth") ||
    haystack.includes("session")
  ) {
    return "authentication";
  }
  if (
    haystack.includes("access-control") ||
    haystack.includes("authoriz") ||
    haystack.includes("idor")
  ) {
    return "authorization";
  }
  if (
    haystack.includes("crypto") ||
    haystack.includes("hash") ||
    haystack.includes("cipher") ||
    haystack.includes("tls")
  ) {
    return "cryptography";
  }
  if (haystack.includes("config") || haystack.includes("cors")) {
    return "misconfiguration";
  }

  return "other";
}

function mapSemgrepSeverity(
  rawSeverity: string,
  metadata: SemgrepCliMetadata | undefined,
  category: VulnerabilityCategory
): Severity {
  const normalized = rawSeverity.toUpperCase();
  const impact = metadata?.impact?.toUpperCase();
  const confidence = metadata?.confidence?.toUpperCase();

  if (normalized === "ERROR" || normalized === "CRITICAL") {
    if (
      impact === "HIGH" &&
      (confidence === "HIGH" ||
        category === "injection" ||
        category === "secrets" ||
        category === "deserialization")
    ) {
      return "critical";
    }
    return "high";
  }

  if (normalized === "WARNING" || normalized === "MEDIUM") {
    return "medium";
  }

  if (normalized === "INFO" || normalized === "LOW") {
    return "low";
  }

  return "medium";
}

function mapSemgrepConfidence(metadata: SemgrepCliMetadata | undefined): number {
  const normalized = metadata?.confidence?.toUpperCase();
  if (normalized === "HIGH") return 0.92;
  if (normalized === "MEDIUM") return 0.78;
  if (normalized === "LOW") return 0.6;
  return 0.82;
}

function formatRuleTitle(checkId: string): string {
  const segments = checkId.split(".");
  const tail = segments[segments.length - 1] ?? checkId;
  return tail
    .split(/[-_]+/)
    .filter((part) => part.length > 0)
    .map((part) => `${part.charAt(0).toUpperCase()}${part.slice(1)}`)
    .join(" ");
}

function mapCliResultToVulnerability(
  result: SemgrepCliResult,
  lines: string[]
): StructuredVulnerability {
  const metadata = result.extra.metadata;
  const category = inferCategory(result.check_id, metadata);
  const severity = mapSemgrepSeverity(result.extra.severity, metadata, category);
  const line = Math.max(1, result.start.line);
  const column = Math.max(1, result.start.col);
  const snippet =
    lines.length > 0
      ? extractCodeSnippet(lines, line, 2)
      : (result.extra.lines ?? "");
  const message =
    result.extra.message.trim() || `Semgrep rule ${result.check_id} matched.`;
  const suggestedFix = result.extra.fix
    ? `Apply the recommended Semgrep remediation: ${result.extra.fix}`
    : `Review and remediate the flagged pattern (${result.check_id}) following secure coding guidelines.`;
  const secureCodeExample =
    result.extra.fix ??
    "// Validate and sanitize untrusted inputs or replace the flagged API with a safe equivalent.";

  return {
    ruleId: result.check_id,
    name: formatRuleTitle(result.check_id),
    severity,
    category,
    cweId: extractCweId(metadata),
    owaspCategory: extractOwaspCategory(metadata),
    description: message,
    risk: message,
    fileLine: line,
    column,
    snippet,
    suggestedFix,
    secureCodeExample,
    confidenceScore: mapSemgrepConfidence(metadata),
  };
}

function parseSemgrepCliOutput(rawStdout: string): SemgrepCliOutput | null {
  const trimmed = rawStdout.trim();
  if (!trimmed) {
    return null;
  }

  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      "results" in parsed &&
      Array.isArray((parsed as { results: unknown }).results)
    ) {
      return parsed as SemgrepCliOutput;
    }
    return null;
  } catch {
    return null;
  }
}

function sortVulnerabilities(
  vulnerabilities: StructuredVulnerability[]
): StructuredVulnerability[] {
  return [...vulnerabilities].sort((a, b) => {
    const severityDiff = compareSeverity(a.severity, b.severity);
    if (severityDiff !== 0) {
      return severityDiff;
    }
    if (a.fileLine !== b.fileLine) {
      return a.fileLine - b.fileLine;
    }
    return a.column - b.column;
  });
}

/**
 * Production-ready Semgrep Security Engine with automatic CLI execution
 * and built-in Semgrep-compatible static rule pack fallback.
 */
export class SemgrepEngine {
  private cliCache: CliAvailabilityCache | null = null;

  /**
   * Detects whether the `semgrep` binary is available on PATH.
   * Result is cached for 60 seconds to avoid repeated process spawns.
   */
  public async checkCliAvailability(): Promise<{
    cliAvailable: boolean;
    cliVersion: string | null;
  }> {
    const now = Date.now();
    if (this.cliCache && now - this.cliCache.checkedAt < CLI_CACHE_TTL_MS) {
      return {
        cliAvailable: this.cliCache.cliAvailable,
        cliVersion: this.cliCache.cliVersion,
      };
    }

    try {
      const { stdout } = await runExecFile(
        "semgrep",
        ["--version"],
        CLI_VERSION_TIMEOUT_MS
      );
      const version = stdout.trim().split(/\r?\n/)[0]?.trim() || null;
      this.cliCache = {
        cliAvailable: true,
        cliVersion: version,
        checkedAt: now,
      };
    } catch {
      this.cliCache = {
        cliAvailable: false,
        cliVersion: null,
        checkedAt: now,
      };
    }

    return {
      cliAvailable: this.cliCache.cliAvailable,
      cliVersion: this.cliCache.cliVersion,
    };
  }

  /**
   * Scans source code with Semgrep CLI when available (and permitted),
   * gracefully falling back to the built-in Semgrep rule pack otherwise.
   */
  public async scan(options: SemgrepScanOptions): Promise<SemgrepScanResult> {
    const startedAt = performance.now();
    const language =
      options.language ?? detectLanguage(options.code, options.fileName);
    const ruleset: SemgrepRuleset = options.ruleset ?? "auto";
    const cliStatus = await this.checkCliAvailability();

    const shouldAttemptCli =
      cliStatus.cliAvailable &&
      options.preferCli !== false &&
      process.env.SEMGREP_MODE !== "builtin";

    if (shouldAttemptCli) {
      const cliAttempt = await this.runCliScan(
        options.code,
        options.fileName,
        language,
        ruleset
      );

      if (cliAttempt.ok) {
        const durationMs = Math.max(
          1,
          Math.round(performance.now() - startedAt)
        );
        return {
          engine: "semgrep",
          engineMode: "cli",
          cliAvailable: cliStatus.cliAvailable,
          cliVersion: cliAttempt.version ?? cliStatus.cliVersion,
          ruleset,
          language,
          findings: sortVulnerabilities(cliAttempt.findings),
          rawMatchCount: cliAttempt.rawMatchCount,
          executedRulesCount: cliAttempt.executedRulesCount,
          durationMs,
        };
      }

      // Graceful fallback to built-in rules if CLI invocation failed or timed out
      const fallback = runBuiltinSemgrepRules(options.code, language, ruleset);
      const durationMs = Math.max(1, Math.round(performance.now() - startedAt));
      return {
        engine: "semgrep",
        engineMode: "builtin-rules",
        cliAvailable: cliStatus.cliAvailable,
        cliVersion: cliStatus.cliVersion,
        ruleset,
        language,
        findings: sortVulnerabilities(fallback.findings),
        rawMatchCount: fallback.rawMatchCount,
        executedRulesCount: fallback.executedRulesCount,
        durationMs,
        fallbackReason: cliAttempt.reason,
      };
    }

    const builtin = runBuiltinSemgrepRules(options.code, language, ruleset);
    const durationMs = Math.max(1, Math.round(performance.now() - startedAt));
    return {
      engine: "semgrep",
      engineMode: "builtin-rules",
      cliAvailable: cliStatus.cliAvailable,
      cliVersion: cliStatus.cliVersion,
      ruleset,
      language,
      findings: sortVulnerabilities(builtin.findings),
      rawMatchCount: builtin.rawMatchCount,
      executedRulesCount: builtin.executedRulesCount,
      durationMs,
    };
  }

  /**
   * Merges Sentinel AI and Semgrep findings, deduplicating overlapping findings
   * on the same line + category by keeping the higher severity / higher confidence entry,
   * and returns the merged list sorted by severity descending then line number ascending.
   */
  public mergeFindings(
    sentinelFindings: StructuredVulnerability[],
    semgrepFindings: StructuredVulnerability[]
  ): StructuredVulnerability[] {
    const mergedByKey = new Map<string, StructuredVulnerability>();

    const upsert = (candidate: StructuredVulnerability): void => {
      const key = `${candidate.fileLine}:${candidate.category}`;
      const existing = mergedByKey.get(key);
      if (!existing) {
        mergedByKey.set(key, candidate);
        return;
      }

      const severityComparison = compareSeverity(
        candidate.severity,
        existing.severity
      );
      if (severityComparison < 0) {
        // candidate has higher severity than existing
        mergedByKey.set(key, candidate);
      } else if (
        severityComparison === 0 &&
        candidate.confidenceScore > existing.confidenceScore
      ) {
        mergedByKey.set(key, candidate);
      }
    };

    for (const finding of sentinelFindings) {
      upsert(finding);
    }
    for (const finding of semgrepFindings) {
      upsert(finding);
    }

    return sortVulnerabilities(Array.from(mergedByKey.values()));
  }

  private async runCliScan(
    code: string,
    fileName: string | undefined,
    language: SupportedLanguage,
    ruleset: SemgrepRuleset
  ): Promise<
    | {
        ok: true;
        findings: StructuredVulnerability[];
        rawMatchCount: number;
        executedRulesCount: number;
        version: string | null;
      }
    | { ok: false; reason: string }
  > {
    let tempDir: string | null = null;

    try {
      tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "sentinel-semgrep-"));
      const safeFileName = sanitizeTempFileName(fileName, language);
      const tempFilePath = path.join(tempDir, safeFileName);
      await fs.writeFile(tempFilePath, code, "utf8");

      let rawStdout = "";
      try {
        const result = await runExecFile(
          "semgrep",
          [
            "scan",
            "--json",
            "--config",
            ruleset,
            "--no-git-ignore",
            "--quiet",
            tempFilePath,
          ],
          CLI_SCAN_TIMEOUT_MS
        );
        rawStdout = result.stdout;
      } catch (execError) {
        const maybeOutput = execError as {
          stdout?: string;
          message?: string;
        };
        if (maybeOutput.stdout && maybeOutput.stdout.trim().startsWith("{")) {
          rawStdout = maybeOutput.stdout;
        } else {
          return {
            ok: false,
            reason:
              maybeOutput.message ??
              "Semgrep CLI execution failed or timed out.",
          };
        }
      }

      const parsed = parseSemgrepCliOutput(rawStdout);
      if (!parsed) {
        return {
          ok: false,
          reason: "Semgrep CLI returned unparseable JSON output.",
        };
      }

      const lines = code.split(/\r?\n/);
      const findings = parsed.results.map((item) =>
        mapCliResultToVulnerability(item, lines)
      );
      const uniqueRules = new Set(parsed.results.map((item) => item.check_id));

      return {
        ok: true,
        findings,
        rawMatchCount: parsed.results.length,
        executedRulesCount: Math.max(uniqueRules.size, parsed.results.length),
        version: parsed.version ?? null,
      };
    } catch (error) {
      return {
        ok: false,
        reason:
          error instanceof Error
            ? error.message
            : "Unexpected error running Semgrep CLI.",
      };
    } finally {
      if (tempDir) {
        await fs
          .rm(tempDir, { recursive: true, force: true })
          .catch(() => undefined);
      }
    }
  }
}

export const defaultSemgrepEngine = new SemgrepEngine();
