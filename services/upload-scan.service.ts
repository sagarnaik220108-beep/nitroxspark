import JSZip from "jszip";
import {
  analyzeCode,
  type StructuredSecurityReport,
  type StructuredVulnerability,
} from "@/security/analyzer";
import type { SupportedLanguage } from "@/types";
import {
  buildScanSummary,
  buildSeverityBreakdown,
  calculateRiskGrade,
  calculateRiskScore,
  compareSeverity,
  hashSourceCode,
  ValidationError,
} from "@/utils";

const URL_FETCH_TIMEOUT_MS = 15000;
const MAX_REDIRECTS = 5;

const IGNORED_ARCHIVE_SEGMENTS = new Set<string>([
  "node_modules",
  ".git",
  ".next",
  "dist",
  "build",
  "out",
  "coverage",
  "vendor",
  "__pycache__",
  ".venv",
  "venv",
  "__macosx",
]);

export const SCANNABLE_TEXT_EXTENSIONS = new Set<string>([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".py",
  ".sql",
  ".java",
  ".go",
  ".php",
  ".rb",
  ".cs",
  ".json",
  ".env",
  ".yaml",
  ".yml",
  ".html",
  ".txt",
]);

export const ALLOWED_UPLOAD_EXTENSIONS = new Set<string>([
  ...SCANNABLE_TEXT_EXTENSIONS,
  ".zip",
]);

export interface HeaderAuditItem {
  header: string;
  present: boolean;
  value: string | null;
  severity: "high" | "medium" | "low";
  recommendation: string;
}

export interface ArchiveScanSummary {
  totalEntries: number;
  scannedFiles: number;
  skippedFiles: number;
  filesWithIssues: Array<{
    filePath: string;
    findingsCount: number;
  }>;
}

export interface FileUploadScanResult {
  source: "file";
  fileName: string;
  language: SupportedLanguage;
  sizeBytes: number;
  code: string;
  report: StructuredSecurityReport;
  archiveSummary?: ArchiveScanSummary;
}

export interface UrlUploadScanResult {
  source: "url";
  fetchedUrl: string;
  resolvedUrl: string;
  fileName: string;
  language: SupportedLanguage;
  contentType: string;
  sizeBytes: number;
  code: string;
  report: StructuredSecurityReport;
  headerAudit: HeaderAuditItem[];
}

export type UploadScanResult = FileUploadScanResult | UrlUploadScanResult;

interface SecurityHeaderSpec {
  header: string;
  severity: "high" | "medium" | "low";
  recommendation: string;
}

const SECURITY_HEADER_SPECS: readonly SecurityHeaderSpec[] = [
  {
    header: "Content-Security-Policy",
    severity: "high",
    recommendation:
      "Define a strict Content-Security-Policy header to restrict script, style, and resource origins against XSS.",
  },
  {
    header: "Strict-Transport-Security",
    severity: "high",
    recommendation:
      "Set Strict-Transport-Security (e.g. max-age=31536000; includeSubDomains) to enforce HTTPS.",
  },
  {
    header: "X-Frame-Options",
    severity: "medium",
    recommendation:
      "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking attacks.",
  },
  {
    header: "X-Content-Type-Options",
    severity: "medium",
    recommendation:
      "Set X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
  },
  {
    header: "Referrer-Policy",
    severity: "low",
    recommendation:
      "Set Referrer-Policy (e.g. strict-origin-when-cross-origin) to limit sensitive URL leakage.",
  },
  {
    header: "Permissions-Policy",
    severity: "low",
    recommendation:
      "Configure Permissions-Policy to disable unused browser features such as camera, microphone, and geolocation.",
  },
];

function sanitizeFileName(rawName: string): string {
  const normalized = rawName.replace(/\\/g, "/");
  const segments = normalized.split("/");
  const base = (segments[segments.length - 1] ?? "").trim();
  return base.length > 0 ? base : "uploaded-file.txt";
}

function extractExtension(fileName: string): string {
  const lower = fileName.toLowerCase();
  if (lower === ".env" || lower.startsWith(".env.")) {
    return ".env";
  }
  const lastDot = lower.lastIndexOf(".");
  if (lastDot <= 0) {
    return "";
  }
  return lower.slice(lastDot);
}

function containsNullByte(bytes: Uint8Array): boolean {
  for (let i = 0; i < bytes.length; i += 1) {
    if (bytes[i] === 0) {
      return true;
    }
  }
  return false;
}

function isBlockedIpv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;

  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return false;
    const num = Number(part);
    if (!Number.isInteger(num) || num < 0 || num > 255) return false;
    octets.push(num);
  }

  const a = octets[0] ?? -1;
  const b = octets[1] ?? -1;

  // 0.0.0.0/8 (unspecified)
  if (a === 0) return true;
  // 10.0.0.0/8 (private)
  if (a === 10) return true;
  // 127.0.0.0/8 (loopback)
  if (a === 127) return true;
  // 169.254.0.0/16 (link-local / cloud metadata)
  if (a === 169 && b === 254) return true;
  // 172.16.0.0/12 (private)
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.168.0.0/16 (private)
  if (a === 192 && b === 168) return true;

  return false;
}

function isBlockedIpv6(rawHost: string): boolean {
  const host = rawHost.toLowerCase();

  // Loopback & unspecified
  if (
    host === "::1" ||
    host === "::" ||
    host === "0:0:0:0:0:0:0:1" ||
    host === "0:0:0:0:0:0:0:0"
  ) {
    return true;
  }

  // Unique local addresses (fc00::/7 -> fc00:..fdff:) and link-local (fe80::/10)
  if (
    host.startsWith("fc00:") ||
    host.startsWith("fd00:") ||
    host.startsWith("fe80:") ||
    /^f[cd][0-9a-f]{2}:/.test(host) ||
    /^fe[89ab][0-9a-f]:/.test(host)
  ) {
    return true;
  }

  // IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1 or ::ffff:7f00:1)
  if (host.startsWith("::ffff:")) {
    const mapped = host.slice("::ffff:".length);
    if (mapped.includes(".")) {
      return isBlockedIpv4(mapped);
    }
    const hexGroups = mapped.split(":");
    if (hexGroups.length === 2) {
      const hi = Number.parseInt(hexGroups[0] ?? "", 16);
      const lo = Number.parseInt(hexGroups[1] ?? "", 16);
      if (!Number.isNaN(hi) && !Number.isNaN(lo)) {
        const ipv4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
        return isBlockedIpv4(ipv4);
      }
    }
  }

  return false;
}

function assertSafeTargetUrl(parsed: URL): void {
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new ValidationError(
      "Only http:// and https:// URLs are permitted for security scanning."
    );
  }

  if (parsed.username || parsed.password) {
    throw new ValidationError(
      "URLs containing embedded credentials are not permitted."
    );
  }

  const rawHost = parsed.hostname.toLowerCase().replace(/\.+$/, "");
  const unbracketedHost =
    rawHost.startsWith("[") && rawHost.endsWith("]")
      ? rawHost.slice(1, -1)
      : rawHost;

  if (!unbracketedHost) {
    throw new ValidationError("Target URL must include a valid hostname.");
  }

  if (
    unbracketedHost === "localhost" ||
    unbracketedHost.endsWith(".localhost") ||
    unbracketedHost.endsWith(".local") ||
    unbracketedHost.endsWith(".internal")
  ) {
    throw new ValidationError(
      "Scanning localhost, .local, or .internal hostnames is blocked by SSRF protection."
    );
  }

  if (isBlockedIpv4(unbracketedHost) || isBlockedIpv6(unbracketedHost)) {
    throw new ValidationError(
      "Scanning private, loopback, or link-local IP addresses is blocked by SSRF protection."
    );
  }
}

function convertGitHubBlobUrl(parsed: URL): URL {
  if (parsed.hostname.toLowerCase() !== "github.com") {
    return parsed;
  }

  // Match /owner/repo/blob/branch/path/to/file
  const match = /^\/([^/]+)\/([^/]+)\/blob\/(.+)$/.exec(parsed.pathname);
  if (!match) {
    return parsed;
  }

  const owner = match[1];
  const repo = match[2];
  const rest = match[3];
  if (!owner || !repo || !rest) {
    return parsed;
  }

  return new URL(`https://raw.githubusercontent.com/${owner}/${repo}/${rest}`);
}

function deriveFileNameFromUrl(resolved: URL, contentType: string): string {
  const segments = resolved.pathname
    .split("/")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const lastSegment = segments[segments.length - 1];

  if (lastSegment) {
    try {
      const decoded = decodeURIComponent(lastSegment);
      const sanitized = sanitizeFileName(decoded);
      if (sanitized.includes(".")) {
        return sanitized;
      }
    } catch {
      const sanitized = sanitizeFileName(lastSegment);
      if (sanitized.includes(".")) {
        return sanitized;
      }
    }
  }

  const host = resolved.hostname.replace(/[^a-zA-Z0-9.-]/g, "_") || "remote";
  if (contentType.toLowerCase().includes("text/html")) {
    return `${host}.html`;
  }
  if (contentType.toLowerCase().includes("application/json")) {
    return `${host}.json`;
  }
  if (contentType.toLowerCase().includes("javascript")) {
    return `${host}.js`;
  }
  return `${host}.txt`;
}

function auditSecurityHeaders(headers: Headers): HeaderAuditItem[] {
  return SECURITY_HEADER_SPECS.map((spec) => {
    const rawValue = headers.get(spec.header);
    const trimmed = rawValue !== null ? rawValue.trim() : null;
    const present = trimmed !== null && trimmed.length > 0;
    return {
      header: spec.header,
      present,
      value: present ? trimmed : null,
      severity: spec.severity,
      recommendation: spec.recommendation,
    };
  });
}

async function readResponseWithLimit(
  response: Response,
  maxBytes: number
): Promise<Uint8Array> {
  const contentLengthHeader = response.headers.get("content-length");
  if (contentLengthHeader) {
    const declaredBytes = Number(contentLengthHeader);
    if (Number.isFinite(declaredBytes) && declaredBytes > maxBytes) {
      throw new ValidationError(
        `Remote response exceeds the maximum allowed size of ${Math.round(
          maxBytes / 1024
        )} KB.`
      );
    }
  }

  if (!response.body) {
    const buffer = new Uint8Array(await response.arrayBuffer());
    if (buffer.byteLength > maxBytes) {
      throw new ValidationError(
        `Remote response exceeds the maximum allowed size of ${Math.round(
          maxBytes / 1024
        )} KB.`
      );
    }
    return buffer;
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;

      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel();
        throw new ValidationError(
          `Remote response exceeds the maximum allowed size of ${Math.round(
            maxBytes / 1024
          )} KB.`
        );
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const combined = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return combined;
}

async function readResponseBytes(response: Response): Promise<Uint8Array> {
  const buffer = await response.arrayBuffer();
  return new Uint8Array(buffer);
}

function isSafeArchiveEntryPath(rawPath: string): boolean {
  const normalized = rawPath.replace(/\\/g, "/").trim();
  if (!normalized || normalized.startsWith("/") || normalized.includes("\0")) {
    return false;
  }
  const segments = normalized.split("/");
  for (const segment of segments) {
    if (segment === "..") return false;
    if (IGNORED_ARCHIVE_SEGMENTS.has(segment.toLowerCase())) {
      return false;
    }
  }
  return true;
}

export class UploadScanService {
  /**
   * Extracts and scans all supported source/config files inside a `.zip` archive
   * (with Zip Slip protection and automatic skipping of node_modules/build/binary files).
   */
  private async scanZipArchive(
    fileName: string,
    bytes: Uint8Array
  ): Promise<FileUploadScanResult> {
    const startedAt = performance.now();
    let zip: JSZip;
    try {
      zip = await JSZip.loadAsync(bytes);
    } catch {
      throw new ValidationError(
        `Unable to read '${fileName}' as a valid .zip archive.`
      );
    }

    const entries = Object.values(zip.files).filter((entry) => !entry.dir);
    let scannedFiles = 0;
    let skippedFiles = 0;
    let totalLineCount = 0;
    let executedRulesCount = 0;

    const aggregatedFindings: StructuredVulnerability[] = [];
    const filesWithIssues: Array<{ filePath: string; findingsCount: number }> = [];
    const previewSections: string[] = [];
    const languageCounts = new Map<SupportedLanguage, number>();

    for (const entry of entries) {
      const normalizedPath = entry.name.replace(/\\/g, "/");
      if (!isSafeArchiveEntryPath(normalizedPath)) {
        skippedFiles += 1;
        continue;
      }

      const entryFileName = sanitizeFileName(normalizedPath);
      const ext = extractExtension(entryFileName);
      if (!SCANNABLE_TEXT_EXTENSIONS.has(ext)) {
        skippedFiles += 1;
        continue;
      }

      const entryBytes = await entry.async("uint8array");
      if (entryBytes.byteLength === 0 || containsNullByte(entryBytes)) {
        skippedFiles += 1;
        continue;
      }

      const entryCode = new TextDecoder("utf-8", { fatal: false }).decode(
        entryBytes
      );
      if (entryCode.trim().length === 0) {
        skippedFiles += 1;
        continue;
      }

      scannedFiles += 1;
      const fileReport = analyzeCode(entryCode, { fileName: normalizedPath });
      totalLineCount += fileReport.lineCount;
      executedRulesCount = Math.max(
        executedRulesCount,
        fileReport.executedRulesCount
      );
      languageCounts.set(
        fileReport.language,
        (languageCounts.get(fileReport.language) ?? 0) + 1
      );

      if (fileReport.vulnerabilities.length > 0) {
        filesWithIssues.push({
          filePath: normalizedPath,
          findingsCount: fileReport.vulnerabilities.length,
        });
        for (const vuln of fileReport.vulnerabilities) {
          aggregatedFindings.push({
            ...vuln,
            name: `[${normalizedPath}] ${vuln.name}`,
          });
        }
      }

      // Include up to 500 KB of combined preview text in the editor for smooth browser rendering
      const currentPreviewLength = previewSections.reduce(
        (acc, part) => acc + part.length,
        0
      );
      if (currentPreviewLength < 500_000) {
        previewSections.push(
          `// ==================== ${normalizedPath} ====================\n${entryCode}`
        );
      }
    }

    if (scannedFiles === 0) {
      throw new ValidationError(
        `No scannable source or config files were found inside '${fileName}'.`
      );
    }

    aggregatedFindings.sort((a, b) => {
      const sev = compareSeverity(a.severity, b.severity);
      if (sev !== 0) return sev;
      return a.fileLine - b.fileLine;
    });

    let dominantLanguage: SupportedLanguage = "unknown";
    let maxLangCount = 0;
    for (const [lang, count] of languageCounts.entries()) {
      if (lang !== "unknown" && count > maxLangCount) {
        dominantLanguage = lang;
        maxLangCount = count;
      }
    }

    const severityBreakdown = buildSeverityBreakdown(aggregatedFindings);
    const riskScore = calculateRiskScore(
      aggregatedFindings.map((f) => ({
        severity: f.severity,
        confidence: f.confidenceScore,
      }))
    );
    const riskGrade = calculateRiskGrade(riskScore);
    const baseSummary = buildScanSummary(
      severityBreakdown,
      riskScore,
      riskGrade
    );
    const durationMs = Math.max(1, Math.round(performance.now() - startedAt));
    const combinedCode = previewSections.join("\n\n");

    const report: StructuredSecurityReport = {
      fileName,
      language: dominantLanguage,
      codeHash: hashSourceCode(combinedCode),
      lineCount: totalLineCount,
      riskScore,
      riskGrade,
      summary: `Scanned ${scannedFiles} file${scannedFiles === 1 ? "" : "s"} in ${fileName}. ${baseSummary}`,
      severityBreakdown,
      vulnerabilities: aggregatedFindings,
      executedRulesCount,
      durationMs,
      generatedAt: new Date().toISOString(),
    };

    return {
      source: "file",
      fileName,
      language: dominantLanguage,
      sizeBytes: bytes.byteLength,
      code: combinedCode,
      report,
      archiveSummary: {
        totalEntries: entries.length,
        scannedFiles,
        skippedFiles,
        filesWithIssues: filesWithIssues.sort(
          (a, b) => b.findingsCount - a.findingsCount
        ),
      },
    };
  }

  /**
   * Validates and scans an uploaded source, config, or `.zip` archive file (no size limit).
   */
  public async scanUploadedFile(file: File): Promise<FileUploadScanResult> {
    const fileName = sanitizeFileName(file.name);
    const extension = extractExtension(fileName);

    if (!ALLOWED_UPLOAD_EXTENSIONS.has(extension)) {
      throw new ValidationError(
        `Unsupported file extension '${extension || "(none)"}'. Supported types: ${Array.from(
          ALLOWED_UPLOAD_EXTENSIONS
        ).join(", ")}.`
      );
    }

    if (file.size === 0) {
      throw new ValidationError("Uploaded file is empty.");
    }

    const bytes = new Uint8Array(await file.arrayBuffer());
    if (bytes.byteLength === 0) {
      throw new ValidationError("Uploaded file is empty.");
    }

    if (extension === ".zip") {
      return this.scanZipArchive(fileName, bytes);
    }

    if (containsNullByte(bytes)) {
      throw new ValidationError(
        `Binary files are not supported ('${fileName}'). Please upload a plain-text source, config, or .zip archive.`
      );
    }

    const code = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    if (code.trim().length === 0) {
      throw new ValidationError("Uploaded file contains only whitespace.");
    }

    const report = analyzeCode(code, { fileName });

    return {
      source: "file",
      fileName,
      language: report.language,
      sizeBytes: bytes.byteLength,
      code,
      report,
    };
  }

  /**
   * Validates a URL with strict SSRF protection, fetches the remote content
   * (auto-converting GitHub blob links to raw URLs), audits HTTP security headers
   * for HTML pages, and runs Sentinel AI static analysis.
   */
  public async scanUrl(rawUrl: string): Promise<UrlUploadScanResult> {
    const trimmed = rawUrl.trim();
    if (!trimmed) {
      throw new ValidationError("A URL is required.");
    }

    let parsedInput: URL;
    try {
      parsedInput = new URL(trimmed);
    } catch {
      throw new ValidationError(
        "Invalid URL format. Provide a full http:// or https:// URL."
      );
    }

    assertSafeTargetUrl(parsedInput);
    const convertedUrl = convertGitHubBlobUrl(parsedInput);
    assertSafeTargetUrl(convertedUrl);

    let currentUrl = convertedUrl;
    let response: Response | null = null;

    for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
      try {
        response = await fetch(currentUrl.toString(), {
          method: "GET",
          redirect: "manual",
          signal: AbortSignal.timeout(URL_FETCH_TIMEOUT_MS),
          headers: {
            "User-Agent": "SentinelAI-SecurityScanner/1.0",
            Accept:
              "text/plain, text/html, application/json, application/javascript, */*;q=0.5",
          },
        });
      } catch (err: unknown) {
        if (
          err instanceof Error &&
          (err.name === "TimeoutError" || err.name === "AbortError")
        ) {
          throw new ValidationError(
            "Timed out after 8 seconds while fetching the target URL."
          );
        }
        throw new ValidationError(
          "Unable to reach the target URL. Check the address and try again."
        );
      }

      if (
        response.status >= 300 &&
        response.status < 400 &&
        response.headers.get("location")
      ) {
        if (hop === MAX_REDIRECTS) {
          throw new ValidationError("Too many redirects while fetching target URL.");
        }
        const location = response.headers.get("location");
        if (!location) break;

        let nextUrl: URL;
        try {
          nextUrl = new URL(location, currentUrl);
        } catch {
          throw new ValidationError("Remote server returned an invalid redirect URL.");
        }
        assertSafeTargetUrl(nextUrl);
        currentUrl = nextUrl;
        continue;
      }

      break;
    }

    if (!response) {
      throw new ValidationError("Failed to retrieve a response from the target URL.");
    }

    if (!response.ok) {
      throw new ValidationError(
        `Remote server responded with HTTP ${response.status} (${response.statusText || "Error"}).`
      );
    }

    const contentType =
      response.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase() ||
      "text/plain";

    const bytes = await readResponseBytes(response);
    if (bytes.byteLength === 0) {
      throw new ValidationError("The remote URL returned an empty response body.");
    }

    if (containsNullByte(bytes)) {
      throw new ValidationError(
        "The target URL returned binary content, which cannot be scanned as source code."
      );
    }

    const code = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    if (code.trim().length === 0) {
      throw new ValidationError(
        "The remote URL returned only whitespace content."
      );
    }

    const fileName = deriveFileNameFromUrl(currentUrl, contentType);
    const headerAudit = contentType.includes("text/html")
      ? auditSecurityHeaders(response.headers)
      : [];

    const report = analyzeCode(code, { fileName });

    return {
      source: "url",
      fetchedUrl: trimmed,
      resolvedUrl: currentUrl.toString(),
      fileName,
      language: report.language,
      contentType,
      sizeBytes: bytes.byteLength,
      code,
      report,
      headerAudit,
    };
  }
}

export const uploadScanService = new UploadScanService();
