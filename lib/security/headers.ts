import { NextResponse } from "next/server";

export interface CspOptions {
  /**
   * Preset profile:
   * - `"api"`: Strictest policy (`default-src 'none'; frame-ancestors 'none'`) for JSON endpoints.
   * - `"document"`: Strict self-only policy suitable for minimal backend status pages.
   */
  profile?: "api" | "document";
  /** Optional directive overrides or additions (merged by directive name). */
  directives?: Partial<Record<string, readonly string[]>>;
}

export interface SecurityHeadersOptions {
  /** CSP configuration. Set `false` to omit CSP on a specific response. */
  csp?: CspOptions | false;
  /** Whether to include HSTS (`Strict-Transport-Security`). Defaults to `true`. */
  includeHsts?: boolean;
  /** Cross-Origin-Resource-Policy value. Defaults to `"same-origin"`. */
  crossOriginResourcePolicy?: "same-origin" | "same-site" | "cross-origin";
}

export interface CorsOptions {
  /** Explicit origin allowlist. Defaults to `NEXT_PUBLIC_APP_URL` + `CORS_ALLOWED_ORIGINS`. */
  allowedOrigins?: readonly string[];
  /** Allowed HTTP methods. Defaults to `["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]`. */
  allowedMethods?: readonly string[];
  /** Allowed request headers. */
  allowedHeaders?: readonly string[];
  /** Response headers exposed to browser clients. */
  exposedHeaders?: readonly string[];
  /** Whether to emit `Access-Control-Allow-Credentials: true`. Defaults to `true`. */
  allowCredentials?: boolean;
  /** Preflight cache max-age in seconds. Defaults to `600`. */
  maxAgeSeconds?: number;
}

const DEFAULT_API_CSP: Record<string, readonly string[]> = {
  "default-src": ["'none'"],
  "base-uri": ["'none'"],
  "form-action": ["'none'"],
  "frame-ancestors": ["'none'"],
};

const DEFAULT_DOCUMENT_CSP: Record<string, readonly string[]> = {
  "default-src": ["'self'"],
  "script-src": ["'self'"],
  "style-src": ["'self'", "'unsafe-inline'"],
  "img-src": ["'self'", "data:"],
  "font-src": ["'self'"],
  "connect-src": ["'self'"],
  "object-src": ["'none'"],
  "base-uri": ["'self'"],
  "form-action": ["'self'"],
  "frame-ancestors": ["'none'"],
  "upgrade-insecure-requests": [],
};

const DEFAULT_ALLOWED_METHODS = [
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
] as const;

const DEFAULT_ALLOWED_HEADERS = [
  "Content-Type",
  "Authorization",
  "X-Requested-With",
  "X-Request-Id",
] as const;

const DEFAULT_EXPOSED_HEADERS = [
  "X-Request-Id",
  "X-RateLimit-Limit",
  "X-RateLimit-Remaining",
  "X-RateLimit-Reset",
  "Retry-After",
  "ETag",
] as const;

function normalizeOrigin(raw: string): string | null {
  try {
    const parsed = new URL(raw.trim());
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }
    return parsed.origin.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Resolves the trusted CORS origin allowlist from environment configuration.
 * Never falls back to wildcard `*` so credentialed requests stay locked down.
 */
export function resolveAllowedOrigins(
  explicitOrigins?: readonly string[]
): string[] {
  const candidates: string[] = [];

  if (explicitOrigins && explicitOrigins.length > 0) {
    candidates.push(...explicitOrigins);
  } else {
    if (process.env.NEXT_PUBLIC_APP_URL) {
      candidates.push(process.env.NEXT_PUBLIC_APP_URL);
    }
    if (process.env.CORS_ALLOWED_ORIGINS) {
      candidates.push(
        ...process.env.CORS_ALLOWED_ORIGINS.split(",").map((item) =>
          item.trim()
        )
      );
    }
  }

  const normalized = new Set<string>();
  for (const candidate of candidates) {
    const origin = normalizeOrigin(candidate);
    if (origin) {
      normalized.add(origin);
    }
  }

  return Array.from(normalized);
}

/**
 * Returns `true` only when the request origin matches the normalized allowlist.
 */
export function isOriginAllowed(
  origin: string | null,
  allowedOrigins?: readonly string[]
): boolean {
  if (!origin) return false;
  const normalizedOrigin = normalizeOrigin(origin);
  if (!normalizedOrigin) return false;

  const allowlist = resolveAllowedOrigins(allowedOrigins);
  return allowlist.includes(normalizedOrigin);
}

/**
 * Builds a strict Content-Security-Policy header string.
 */
export function buildCspHeader(options: CspOptions = {}): string {
  const base =
    options.profile === "document" ? DEFAULT_DOCUMENT_CSP : DEFAULT_API_CSP;
  const merged: Record<string, readonly string[]> = { ...base };

  if (options.directives) {
    for (const [directive, values] of Object.entries(options.directives)) {
      if (values !== undefined) {
        merged[directive] = values;
      }
    }
  }

  return Object.entries(merged)
    .map(([directive, values]) =>
      values.length > 0 ? `${directive} ${values.join(" ")}` : directive
    )
    .join("; ");
}

/**
 * Builds Sentinel AI's production HTTP security headers.
 */
export function buildSecurityHeaders(
  options: SecurityHeadersOptions = {}
): Record<string, string> {
  const headers: Record<string, string> = {
    "X-DNS-Prefetch-Control": "off",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy":
      "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy":
      options.crossOriginResourcePolicy ?? "same-origin",
  };

  if (options.includeHsts !== false) {
    headers["Strict-Transport-Security"] =
      "max-age=63072000; includeSubDomains; preload";
  }

  if (options.csp !== false) {
    headers["Content-Security-Policy"] = buildCspHeader(options.csp);
  }

  return headers;
}

/**
 * Applies production security headers to a `Response` / `NextResponse` without
 * clobbering existing headers unless overwritten.
 */
export function applySecurityHeaders<T extends Response>(
  response: T,
  options: SecurityHeadersOptions = {}
): T {
  const securityHeaders = buildSecurityHeaders(options);
  for (const [key, value] of Object.entries(securityHeaders)) {
    if (!response.headers.has(key)) {
      response.headers.set(key, value);
    }
  }
  return response;
}

/**
 * Builds validated CORS headers for an incoming `Origin`.
 * Returns an empty object when the origin is absent or not on the allowlist.
 */
export function buildCorsHeaders(
  origin: string | null,
  options: CorsOptions = {}
): Record<string, string> {
  if (!isOriginAllowed(origin, options.allowedOrigins) || !origin) {
    return {};
  }

  const normalizedOrigin = normalizeOrigin(origin);
  if (!normalizedOrigin) {
    return {};
  }

  const headers: Record<string, string> = {
    "Access-Control-Allow-Origin": normalizedOrigin,
    "Access-Control-Allow-Methods": (
      options.allowedMethods ?? DEFAULT_ALLOWED_METHODS
    ).join(", "),
    "Access-Control-Allow-Headers": (
      options.allowedHeaders ?? DEFAULT_ALLOWED_HEADERS
    ).join(", "),
    "Access-Control-Expose-Headers": (
      options.exposedHeaders ?? DEFAULT_EXPOSED_HEADERS
    ).join(", "),
    "Access-Control-Max-Age": String(
      Math.max(0, Math.floor(options.maxAgeSeconds ?? 600))
    ),
    Vary: "Origin",
  };

  if (options.allowCredentials !== false) {
    headers["Access-Control-Allow-Credentials"] = "true";
  }

  return headers;
}

/**
 * Applies origin-validated CORS headers to an existing response and safely
 * appends `Origin` to the `Vary` header.
 */
export function applyCorsHeaders<T extends Response>(
  response: T,
  origin: string | null,
  options: CorsOptions = {}
): T {
  const corsHeaders = buildCorsHeaders(origin, options);
  for (const [key, value] of Object.entries(corsHeaders)) {
    if (key.toLowerCase() === "vary") {
      const existingVary = response.headers.get("Vary");
      if (!existingVary) {
        response.headers.set("Vary", value);
      } else {
        const parts = existingVary
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean);
        if (!parts.some((item) => item.toLowerCase() === "origin")) {
          response.headers.set("Vary", [...parts, "Origin"].join(", "));
        }
      }
      continue;
    }

    response.headers.set(key, value);
  }

  return response;
}

/**
 * Handles CORS `OPTIONS` preflight requests with strict origin validation.
 * Rejects disallowed origins with HTTP 403.
 */
export function createCorsPreflightResponse(
  request: Request,
  options: CorsOptions = {}
): NextResponse {
  const origin = request.headers.get("origin");
  if (!origin || !isOriginAllowed(origin, options.allowedOrigins)) {
    const forbidden = new NextResponse(null, { status: 403 });
    return applySecurityHeaders(forbidden);
  }

  const preflight = new NextResponse(null, { status: 204 });
  applyCorsHeaders(preflight, origin, options);
  return applySecurityHeaders(preflight);
}
