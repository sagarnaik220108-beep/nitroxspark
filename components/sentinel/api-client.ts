import type { StructuredSecurityReport } from "@/security/analyzer";
import type {
  ApiResponse,
  BatchSecureFixResult,
  BeginnerFriendlyExplanation,
  FileAttackRunResponse,
  FixVulnerabilityInput,
  GeneratedReportBundle,
  ReportGeneratorInput,
  ReportOutputFormat,
  SecureFixResult,
  SecurityScoreInput,
  SecurityScoreReport,
  SemgrepRuleset,
  SemgrepServiceScanResponse,
  SemgrepStatusResponse,
  SimulationAttackType,
  SimulationCodeContext,
  SimulationRunResponse,
  SupportedLanguage,
  VulnerabilityExplanationInput,
} from "@/types";

export class SentinelApiError extends Error {
  public readonly status: number;
  public readonly code: string;
  public readonly details?: unknown;

  constructor(
    message: string,
    status: number,
    code = "API_ERROR",
    details?: unknown
  ) {
    super(message);
    this.name = "SentinelApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export interface AnalyzeCodeApiParams {
  code: string;
  fileName?: string;
  language?: SupportedLanguage;
  enabledRuleIds?: string[];
  disabledRuleIds?: string[];
}

export interface GenerateFixApiParams {
  originalCode: string;
  vulnerability: FixVulnerabilityInput;
}

export interface GenerateBatchFixApiParams {
  originalCode: string;
  vulnerabilities: FixVulnerabilityInput[];
}

export interface AuthUserRecord {
  id: string;
  email: string;
  created_at: string;
  last_login: string;
}

export interface AuthSessionMetadata {
  expiresAt: number | null;
  provider: string | null;
}

export interface AuthSessionResponse {
  authenticated: boolean;
  user: AuthUserRecord | null;
  session: AuthSessionMetadata | null;
}

export interface GoogleLoginResponse {
  url: string;
  provider: "google";
}

export interface LogoutResponse {
  signedOut: boolean;
}

interface GenerateReportApiRawData {
  format: ReportOutputFormat;
  reportId: string;
  generatedAt: string;
  report: GeneratedReportBundle["canonical"];
  json?: GeneratedReportBundle["json"];
  html?: GeneratedReportBundle["html"];
  pdfReady?: GeneratedReportBundle["pdfReady"];
  exportMetadata: GeneratedReportBundle["exportMetadata"];
}

async function requestJson<T>(
  url: string,
  init: RequestInit = {}
): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(url, {
    ...init,
    headers,
    credentials: "same-origin",
  });

  let payload: ApiResponse<T> | null = null;
  try {
    payload = (await response.json()) as ApiResponse<T>;
  } catch {
    throw new SentinelApiError(
      `Unexpected non-JSON response (${response.status})`,
      response.status,
      "INVALID_RESPONSE"
    );
  }

  if (!response.ok || !payload.success) {
    const err = !payload.success ? payload.error : undefined;
    throw new SentinelApiError(
      err?.message ?? `Request failed with status ${response.status}`,
      response.status,
      err?.code ?? "REQUEST_FAILED",
      err?.details
    );
  }

  return payload.data;
}

function extractFilenameFromDisposition(
  headerValue: string | null,
  fallback: string
): string {
  if (!headerValue) return fallback;
  const match = /filename="?([^";\n]+)"?/i.exec(headerValue);
  const extracted = match?.[1]?.trim();
  return extracted && extracted.length > 0 ? extracted : fallback;
}

/**
 * POST /api/analyze
 * Runs the 12-rule modular static security analysis engine on source code.
 */
export async function analyzeCodeApi(
  params: AnalyzeCodeApiParams
): Promise<StructuredSecurityReport> {
  return requestJson<StructuredSecurityReport>("/api/analyze", {
    method: "POST",
    body: JSON.stringify(params),
  });
}

/**
 * POST /api/explain
 * Generates a beginner-friendly explanation for a single detected vulnerability.
 */
export async function explainVulnerabilityApi(
  vulnerability: VulnerabilityExplanationInput,
  useAI?: boolean
): Promise<BeginnerFriendlyExplanation> {
  const data = await requestJson<{ explanation: BeginnerFriendlyExplanation }>(
    "/api/explain",
    {
      method: "POST",
      body: JSON.stringify({
        vulnerability,
        ...(useAI !== undefined ? { useAI } : {}),
      }),
    }
  );
  return data.explanation;
}

/**
 * POST /api/fix
 * Generates a deterministic secure code fix for a single vulnerability.
 */
export async function generateFixApi(
  params: GenerateFixApiParams
): Promise<SecureFixResult> {
  return requestJson<SecureFixResult>("/api/fix", {
    method: "POST",
    body: JSON.stringify(params),
  });
}

/**
 * POST /api/fix
 * Generates a combined secure code fix for multiple vulnerabilities in one pass.
 */
export async function generateBatchFixApi(
  params: GenerateBatchFixApiParams
): Promise<BatchSecureFixResult> {
  return requestJson<BatchSecureFixResult>("/api/fix", {
    method: "POST",
    body: JSON.stringify(params),
  });
}

/**
 * POST /api/attack/file
 * Runs 100% simulated before-vs-after attack simulations directly on the
 * user's active file and its detected vulnerabilities.
 */
export async function runFileAttackSimulationApi(params: {
  code: string;
  fileName: string;
  language?: SupportedLanguage;
  vulnerabilities?: StructuredSecurityReport["vulnerabilities"];
}): Promise<FileAttackRunResponse> {
  return requestJson<FileAttackRunResponse>("/api/attack/file", {
    method: "POST",
    body: JSON.stringify(params),
  });
}

/**
 * POST /api/attack
 * Executes a 100% synthetic Before-vs-After defensive attack simulation.
 */
export async function runAttackSimulationApi(
  attackType?: SimulationAttackType,
  codeContext?: SimulationCodeContext
): Promise<SimulationRunResponse> {
  const payload: Record<string, unknown> = {};
  if (attackType) {
    payload.attackType = attackType;
  }
  if (codeContext) {
    payload.codeContext = codeContext;
  }

  return requestJson<SimulationRunResponse>("/api/attack", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

/**
 * POST /api/score
 * Computes a standardized security posture score report from scan metrics.
 */
export async function calculateScoreApi(
  input: SecurityScoreInput
): Promise<SecurityScoreReport> {
  return requestJson<SecurityScoreReport>("/api/score", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

/**
 * POST /api/reports/generate
 * Generates a security report bundle (JSON, HTML, PDF-Ready AST, or all).
 * When `format === "html"` and `download === true`, triggers a browser file download
 * of the self-contained HTML5 report and returns `null`.
 */
export async function generateReportApi(
  input: ReportGeneratorInput,
  format: ReportOutputFormat = "all",
  download = false
): Promise<GeneratedReportBundle | null> {
  const body = JSON.stringify({
    ...input,
    format,
    download,
  });

  if (format === "html" && download) {
    const response = await fetch("/api/reports/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      credentials: "same-origin",
    });

    if (!response.ok) {
      let message = `Failed to download report (${response.status})`;
      let code = "REPORT_DOWNLOAD_FAILED";
      try {
        const errPayload = (await response.json()) as ApiResponse<never>;
        if (!errPayload.success) {
          message = errPayload.error.message;
          code = errPayload.error.code;
        }
      } catch {
        // Ignore JSON parse error for non-JSON error responses
      }
      throw new SentinelApiError(message, response.status, code);
    }

    const blob = await response.blob();
    const fileName = extractFilenameFromDisposition(
      response.headers.get("Content-Disposition"),
      "sentinel-security-report.html"
    );

    if (typeof window !== "undefined") {
      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = fileName;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(objectUrl);
    }

    return null;
  }

  const data = await requestJson<GenerateReportApiRawData>(
    "/api/reports/generate",
    {
      method: "POST",
      body,
    }
  );

  return {
    reportId: data.reportId,
    generatedAt: data.generatedAt,
    canonical: data.report,
    ...(data.json ? { json: data.json } : {}),
    ...(data.html ? { html: data.html } : {}),
    ...(data.pdfReady ? { pdfReady: data.pdfReady } : {}),
    exportMetadata: data.exportMetadata,
  };
}

/**
 * GET /api/auth/session
 * Returns the active Supabase authentication session and synced user record.
 */
export async function getSessionApi(): Promise<AuthSessionResponse> {
  return requestJson<AuthSessionResponse>("/api/auth/session", {
    method: "GET",
    cache: "no-store",
  });
}

/**
 * POST /api/auth/google
 * Initiates Supabase Google OAuth flow and returns the provider redirect URL.
 */
export async function initiateGoogleLoginApi(
  next?: string
): Promise<GoogleLoginResponse> {
  return requestJson<GoogleLoginResponse>("/api/auth/google", {
    method: "POST",
    body: JSON.stringify(next ? { next } : {}),
  });
}

/**
 * POST /api/auth/logout
 * Signs out the active user session and clears auth cookies.
 */
export async function logoutApi(): Promise<LogoutResponse> {
  return requestJson<LogoutResponse>("/api/auth/logout", {
    method: "POST",
  });
}

/**
 * GET /api/semgrep
 * Returns Semgrep engine availability, mode (cli or builtin-rules), and rulesets.
 */
export async function getSemgrepStatusApi(): Promise<SemgrepStatusResponse> {
  return requestJson<SemgrepStatusResponse>("/api/semgrep", {
    method: "GET",
    cache: "no-store",
  });
}

/**
 * POST /api/semgrep
 * Runs the Semgrep engine (optionally combined with Sentinel AI's 12-rule engine).
 */
export async function scanWithSemgrepApi(params: {
  code: string;
  fileName?: string;
  language?: SupportedLanguage;
  ruleset?: SemgrepRuleset;
  combineWithSentinel?: boolean;
}): Promise<SemgrepServiceScanResponse> {
  return requestJson<SemgrepServiceScanResponse>("/api/semgrep", {
    method: "POST",
    body: JSON.stringify({
      combineWithSentinel: true,
      ...params,
    }),
  });
}
