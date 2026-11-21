import type { NextRequest, NextResponse } from "next/server";
import type { z } from "zod";
import { requireAuthMiddleware, type RouteHandlerContext } from "@/lib/auth/middleware";
import { buildCacheHeaders, type HttpCacheHeaderOptions } from "@/lib/cache";
import { logger } from "@/lib/logger";
import { checkRateLimit, type RateLimitConfig } from "@/lib/rate-limit";
import {
  applyCorsHeaders,
  applySecurityHeaders,
  type CorsOptions,
  type SecurityHeadersOptions,
} from "@/lib/security/headers";
import type { AuthenticatedContext } from "@/services/auth.service";
import { apiError, handleRouteError, ValidationError } from "@/utils";

export type RateLimitTier = "standard" | "scan" | "ai" | "strict";

export interface ApiRateLimitOption extends RateLimitConfig {
  /** Optional prefix used to isolate buckets per route or feature. */
  keyPrefix?: string;
}

export const RATE_LIMIT_TIERS: Readonly<Record<RateLimitTier, RateLimitConfig>> = {
  standard: { maxRequests: 60, windowMs: 60_000 },
  scan: { maxRequests: 30, windowMs: 60_000 },
  ai: { maxRequests: 15, windowMs: 60_000 },
  strict: { maxRequests: 10, windowMs: 60_000 },
};

export interface CreateApiHandlerOptions<
  TBody = unknown,
  TRequireAuth extends boolean = false,
> {
  /** When `true`, verifies the Supabase session before running the handler. */
  requireAuth?: TRequireAuth;
  /** Tiered or custom rate limiting configuration. */
  rateLimit?: RateLimitTier | ApiRateLimitOption | false;
  /** Optional Zod schema used to parse and validate the JSON request body. */
  bodySchema?: z.ZodType<TBody, z.ZodTypeDef, unknown>;
  /** Optional CORS configuration. Pass `true` for default allowlist enforcement. */
  cors?: CorsOptions | boolean;
  /** Optional HTTP cache control headers applied to successful responses. */
  cacheControl?: HttpCacheHeaderOptions;
  /** Optional security header overrides. */
  securityHeaders?: SecurityHeadersOptions;
  /** Optional route label for structured request telemetry. */
  routeName?: string;
}

export interface ApiHandlerContext<
  TBody = unknown,
  TRequireAuth extends boolean = false,
  TParams extends Record<string, string | string[]> = Record<string, string>,
> {
  request: NextRequest;
  auth: TRequireAuth extends true
    ? AuthenticatedContext
    : AuthenticatedContext | null;
  body: TBody;
  params: Promise<TParams>;
  requestId: string;
  clientIp: string;
}

export type ComposableApiHandler<
  TBody = unknown,
  TRequireAuth extends boolean = false,
  TParams extends Record<string, string | string[]> = Record<string, string>,
> = (
  context: ApiHandlerContext<TBody, TRequireAuth, TParams>
) => Promise<NextResponse> | NextResponse;

function resolveClientIp(request: NextRequest): string {
  const forwardedFor = request.headers.get("x-forwarded-for");
  if (forwardedFor) {
    const firstIp = forwardedFor.split(",")[0]?.trim();
    if (firstIp) return firstIp;
  }

  const realIp = request.headers.get("x-real-ip")?.trim();
  if (realIp) return realIp;

  return "unknown";
}

function resolveRateLimitConfig(
  option: RateLimitTier | ApiRateLimitOption | false | undefined
): (RateLimitConfig & { keyPrefix?: string }) | null {
  if (!option) return null;
  if (typeof option === "string") {
    return { ...RATE_LIMIT_TIERS[option], keyPrefix: option };
  }
  return option;
}

function attachHeaders(
  response: NextResponse,
  headers: Record<string, string>
): NextResponse {
  for (const [key, value] of Object.entries(headers)) {
    response.headers.set(key, value);
  }
  return response;
}

/**
 * Composable production API Route Handler wrapper for Sentinel AI.
 *
 * Combines:
 * - Optional Supabase authentication (`requireAuth`)
 * - Tiered sliding-window rate limiting with `X-RateLimit-*` & `Retry-After` headers
 * - Strict Zod JSON body parsing and validation (`bodySchema`)
 * - Structured request/response latency logging (`logger`)
 * - Production security headers, optional CORS allowlist, and HTTP cache headers
 * - Unified error normalization (`handleRouteError`)
 */
export function createApiHandler<
  TBody = unknown,
  TRequireAuth extends boolean = false,
  TParams extends Record<string, string | string[]> = Record<string, string>,
>(
  options: CreateApiHandlerOptions<TBody, TRequireAuth>,
  handler: ComposableApiHandler<TBody, TRequireAuth, TParams>
): (
  request: NextRequest,
  routeContext?: RouteHandlerContext<TParams>
) => Promise<NextResponse> {
  return async (
    request: NextRequest,
    routeContext?: RouteHandlerContext<TParams>
  ): Promise<NextResponse> => {
    const startedAt = performance.now();
    const requestId = request.headers.get("x-request-id") ?? crypto.randomUUID();
    const pathname = request.nextUrl.pathname;
    const method = request.method;
    const clientIp = resolveClientIp(request);
    const origin = request.headers.get("origin");
    const routeLabel = options.routeName ?? pathname;

    const rateLimitHeaders: Record<string, string> = {};
    let authenticatedUserId: string | undefined;

    const finalizeResponse = (
      response: NextResponse,
      isSuccess: boolean
    ): NextResponse => {
      response.headers.set("X-Request-Id", requestId);
      attachHeaders(response, rateLimitHeaders);

      if (isSuccess && options.cacheControl) {
        attachHeaders(response, buildCacheHeaders(options.cacheControl));
      } else if (!isSuccess && !response.headers.has("Cache-Control")) {
        response.headers.set("Cache-Control", "no-store");
      }

      if (options.cors) {
        const corsConfig = options.cors === true ? {} : options.cors;
        applyCorsHeaders(response, origin, corsConfig);
      }

      applySecurityHeaders(response, options.securityHeaders);

      const durationMs = Math.round((performance.now() - startedAt) * 100) / 100;
      const logPayload: Record<string, unknown> = {
        requestId,
        route: routeLabel,
        method,
        path: pathname,
        status: response.status,
        durationMs,
        ...(authenticatedUserId ? { userId: authenticatedUserId } : {}),
      };

      if (response.status >= 500) {
        logger.error("API request failed", logPayload);
      } else if (response.status >= 400) {
        logger.warn("API request rejected", logPayload);
      } else {
        logger.info("API request completed", logPayload);
      }

      return response;
    };

    try {
      // 1. Optional Authentication Guard
      let authContext: AuthenticatedContext | null = null;
      if (options.requireAuth) {
        const authResult = await requireAuthMiddleware();
        if (!authResult.authenticated) {
          return finalizeResponse(authResult.response, false);
        }
        authContext = authResult.context;
        authenticatedUserId = authContext.user.id;
      }

      // 2. Tiered Rate Limiting
      const rateLimitConfig = resolveRateLimitConfig(options.rateLimit);
      if (rateLimitConfig) {
        const identity = authenticatedUserId ?? clientIp;
        const prefix = rateLimitConfig.keyPrefix ?? routeLabel;
        const bucketKey = `${prefix}:${identity}`;
        const rateResult = checkRateLimit(bucketKey, rateLimitConfig);

        const resetEpochSeconds = Math.ceil(rateResult.resetAtMs / 1000);
        rateLimitHeaders["X-RateLimit-Limit"] = String(
          rateLimitConfig.maxRequests
        );
        rateLimitHeaders["X-RateLimit-Remaining"] = String(
          rateResult.remaining
        );
        rateLimitHeaders["X-RateLimit-Reset"] = String(resetEpochSeconds);

        if (!rateResult.allowed) {
          const retryAfterSeconds = Math.max(
            1,
            Math.ceil((rateResult.resetAtMs - Date.now()) / 1000)
          );
          rateLimitHeaders["Retry-After"] = String(retryAfterSeconds);

          const rateLimitResponse = apiError(
            "RATE_LIMIT_EXCEEDED",
            `Rate limit exceeded. Retry in ${retryAfterSeconds} second(s).`,
            429,
            { retryAfterSeconds }
          );
          return finalizeResponse(rateLimitResponse, false);
        }
      }

      // 3. Optional Zod Body Parsing & Validation
      let parsedBody: unknown = undefined;
      if (options.bodySchema) {
        let rawJson: unknown;
        try {
          rawJson = await request.json();
        } catch {
          throw new ValidationError("Request body must be valid JSON");
        }

        const validation = options.bodySchema.safeParse(rawJson);
        if (!validation.success) {
          throw new ValidationError(
            "Request validation failed",
            validation.error.flatten().fieldErrors
          );
        }
        parsedBody = validation.data;
      }

      // 4. Execute Domain Handler
      const paramsPromise =
        routeContext?.params ?? Promise.resolve({} as TParams);

      const response = await handler({
        request,
        auth: authContext as TRequireAuth extends true
          ? AuthenticatedContext
          : AuthenticatedContext | null,
        body: parsedBody as TBody,
        params: paramsPromise,
        requestId,
        clientIp,
      });

      return finalizeResponse(response, response.status < 400);
    } catch (error) {
      const errorResponse = handleRouteError(error);
      return finalizeResponse(errorResponse, false);
    }
  };
}
