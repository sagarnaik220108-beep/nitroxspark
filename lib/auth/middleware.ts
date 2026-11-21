import type { NextRequest, NextResponse } from "next/server";
import type { ApiErrorResponse } from "@/types";
import {
  authService,
  type AuthenticatedContext,
} from "@/services/auth.service";
import { apiError, handleRouteError, UnauthorizedError } from "@/utils";

export type AuthMiddlewareResult =
  | {
      authenticated: true;
      context: AuthenticatedContext;
    }
  | {
      authenticated: false;
      response: NextResponse<ApiErrorResponse>;
    };

export interface RouteHandlerContext<
  TParams extends Record<string, string | string[]> = Record<string, string>,
> {
  params: Promise<TParams>;
}

export type AuthenticatedRouteHandler<
  TParams extends Record<string, string | string[]> = Record<string, string>,
> = (
  request: NextRequest,
  auth: AuthenticatedContext,
  routeContext: RouteHandlerContext<TParams>
) => Promise<NextResponse> | NextResponse;

/**
 * Validates the active Supabase session for an incoming Route Handler request.
 * Returns `{ authenticated: true, context: { user, supabase } }` when valid,
 * or a standardized 401 JSON response when unauthenticated.
 */
export async function requireAuthMiddleware(): Promise<AuthMiddlewareResult> {
  try {
    const context = await authService.requireAuthenticatedUser();
    return { authenticated: true, context };
  } catch (error) {
    if (error instanceof UnauthorizedError) {
      return {
        authenticated: false,
        response: apiError(
          error.code,
          error.message,
          error.statusCode,
          undefined,
          { "Cache-Control": "no-store" }
        ),
      };
    }

    return {
      authenticated: false,
      response: handleRouteError(error),
    };
  }
}

/**
 * Higher-order Route Handler wrapper that enforces Supabase authentication
 * before invoking the handler with `{ user, supabase }`.
 */
export function withAuth<
  TParams extends Record<string, string | string[]> = Record<string, string>,
>(
  handler: AuthenticatedRouteHandler<TParams>
): (
  request: NextRequest,
  routeContext: RouteHandlerContext<TParams>
) => Promise<NextResponse> {
  return async (
    request: NextRequest,
    routeContext: RouteHandlerContext<TParams>
  ): Promise<NextResponse> => {
    const authResult = await requireAuthMiddleware();
    if (!authResult.authenticated) {
      return authResult.response;
    }

    try {
      return await handler(request, authResult.context, routeContext);
    } catch (error) {
      return handleRouteError(error);
    }
  };
}
