import { NextResponse } from "next/server";
import { ZodError } from "zod";
import type {
  ActionResult,
  ApiErrorResponse,
  ApiSuccessResponse,
  PaginationMeta,
} from "@/types";
import { AppError } from "./errors";

function createMeta(pagination?: PaginationMeta) {
  return {
    requestId: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    ...(pagination ? { pagination } : {}),
  };
}

/**
 * Returns a standardized JSON success response from a Next.js Route Handler.
 */
export function apiSuccess<T>(
  data: T,
  status = 200,
  pagination?: PaginationMeta,
  headers?: HeadersInit
): NextResponse<ApiSuccessResponse<T>> {
  return NextResponse.json(
    {
      success: true,
      data,
      meta: createMeta(pagination),
    },
    { status, headers }
  );
}

/**
 * Returns a standardized JSON error response from a Next.js Route Handler.
 */
export function apiError(
  code: string,
  message: string,
  status = 500,
  details?: unknown,
  headers?: HeadersInit
): NextResponse<ApiErrorResponse> {
  return NextResponse.json(
    {
      success: false,
      error: {
        code,
        message,
        ...(details !== undefined ? { details } : {}),
      },
      meta: createMeta(),
    },
    { status, headers }
  );
}

/**
 * Normalizes any thrown error (AppError, ZodError, or unknown) into a safe JSON NextResponse.
 * Never leaks internal stack traces to API consumers in production.
 */
export function handleRouteError(error: unknown): NextResponse<ApiErrorResponse> {
  if (error instanceof ZodError) {
    return apiError(
      "VALIDATION_ERROR",
      "Request validation failed",
      400,
      error.flatten().fieldErrors
    );
  }

  if (error instanceof AppError) {
    return apiError(error.code, error.message, error.statusCode, error.details);
  }

  console.error("[Sentinel AI] Unhandled route error:", error);
  return apiError(
    "INTERNAL_SERVER_ERROR",
    "An unexpected error occurred while processing the request.",
    500
  );
}

/**
 * Converts a thrown error into a standardized Server Action error object.
 */
export function handleActionError(error: unknown): ActionResult<never> {
  if (error instanceof ZodError) {
    return {
      success: false,
      error: {
        code: "VALIDATION_ERROR",
        message: "Input validation failed",
        details: error.flatten().fieldErrors,
      },
    };
  }

  if (error instanceof AppError) {
    return {
      success: false,
      error: {
        code: error.code,
        message: error.message,
        details: error.details,
      },
    };
  }

  console.error("[Sentinel AI] Unhandled server action error:", error);
  return {
    success: false,
    error: {
      code: "INTERNAL_SERVER_ERROR",
      message: "An unexpected error occurred.",
    },
  };
}
