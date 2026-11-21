import { createHash } from "node:crypto";
import type { SupportedLanguage } from "@/types";

const EXTENSION_LANGUAGE_MAP: Record<string, SupportedLanguage> = {
  ts: "typescript",
  tsx: "typescript",
  mts: "typescript",
  cts: "typescript",
  js: "javascript",
  jsx: "javascript",
  mjs: "javascript",
  cjs: "javascript",
  py: "python",
  sql: "sql",
  java: "java",
  go: "go",
  php: "php",
  rb: "ruby",
  cs: "csharp",
};

/**
 * Infers the programming language from file extension with content-based fallback.
 */
export function detectLanguage(
  code: string,
  fileName?: string
): SupportedLanguage {
  if (fileName) {
    const ext = fileName.split(".").pop()?.toLowerCase();
    if (ext && EXTENSION_LANGUAGE_MAP[ext]) {
      return EXTENSION_LANGUAGE_MAP[ext];
    }
  }

  if (/\b(interface\s+\w+|type\s+\w+\s*=|:\s*(string|number|boolean)\b)/.test(code)) {
    return "typescript";
  }
  if (/\b(def\s+\w+\(|import\s+\w+|from\s+\w+\s+import)\b/.test(code)) {
    return "python";
  }
  if (/\b(SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET)\b/i.test(code)) {
    return "sql";
  }
  if (/\b(package\s+main|func\s+\w+\(|fmt\.Print)/.test(code)) {
    return "go";
  }
  if (/<\?php|\$\w+\s*=/.test(code)) {
    return "php";
  }
  if (/\b(const|let|var|function|async\s+function|export\s+default)\b/.test(code)) {
    return "javascript";
  }

  return "unknown";
}

/**
 * Computes a deterministic SHA-256 hash of source code for deduplication and integrity checks.
 */
export function hashSourceCode(code: string): string {
  return createHash("sha256").update(code, "utf8").digest("hex");
}

/**
 * Maps a character offset in a source string to 1-based line and column coordinates.
 */
export function offsetToLineColumn(
  code: string,
  offset: number
): { line: number; column: number } {
  const safeOffset = Math.max(0, Math.min(offset, code.length));
  const prefix = code.slice(0, safeOffset);
  const lines = prefix.split("\n");
  const line = lines.length;
  const lastLine = lines[lines.length - 1] ?? "";
  const column = lastLine.length + 1;
  return { line, column };
}

/**
 * Extracts a formatted, line-numbered code snippet surrounding the target line.
 */
export function extractCodeSnippet(
  lines: string[],
  targetLine: number,
  contextLines = 2
): string {
  const start = Math.max(0, targetLine - 1 - contextLines);
  const end = Math.min(lines.length, targetLine + contextLines);
  return lines
    .slice(start, end)
    .map((lineText, idx) => {
      const lineNum = start + idx + 1;
      const marker = lineNum === targetLine ? ">" : " ";
      return `${marker} ${String(lineNum).padStart(4, " ")} | ${lineText}`;
    })
    .join("\n");
}

/**
 * Redacts high-entropy secret substrings so raw credentials are never stored verbatim in logs or snippets.
 */
export function redactSecretValue(value: string): string {
  if (value.length <= 10) {
    return "***REDACTED***";
  }
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}
