import { NextResponse, type NextRequest } from "next/server";
import { authService, sanitizeRedirectPath } from "@/services/auth.service";
import { apiError, apiSuccess, handleRouteError } from "@/utils";

function wantsJson(request: NextRequest): boolean {
  const accept = request.headers.get("accept") ?? "";
  return accept.toLowerCase().includes("application/json");
}

function buildErrorRedirect(
  origin: string,
  errorCode: string,
  message: string
): NextResponse {
  const errorUrl = new URL("/", origin);
  errorUrl.searchParams.set("auth_error", errorCode);
  errorUrl.searchParams.set("auth_error_description", message);
  return NextResponse.redirect(errorUrl);
}

/**
 * GET /auth/callback
 * Handles the Google OAuth callback from Supabase Auth:
 * - Exchanges the `code` query parameter for a verified session
 * - Upserts `public.users` and records `last_login`
 * - Returns JSON if `Accept: application/json`, otherwise redirects safely
 */
export async function GET(request: NextRequest) {
  const { searchParams, origin } = request.nextUrl;
  const oauthError = searchParams.get("error");
  const oauthErrorDescription = searchParams.get("error_description");
  const code = searchParams.get("code");
  const safeNext = sanitizeRedirectPath(searchParams.get("next"), "/dashboard");
  const jsonResponse = wantsJson(request);

  if (oauthError) {
    const message =
      oauthErrorDescription ?? "Google OAuth authentication was cancelled or failed";
    if (jsonResponse) {
      return apiError("OAUTH_ERROR", message, 400, { providerError: oauthError }, {
        "Cache-Control": "no-store",
      });
    }
    return buildErrorRedirect(origin, oauthError, message);
  }

  if (!code) {
    const message = "Missing OAuth authorization code";
    if (jsonResponse) {
      return apiError("VALIDATION_ERROR", message, 400, undefined, {
        "Cache-Control": "no-store",
      });
    }
    return buildErrorRedirect(origin, "missing_code", message);
  }

  try {
    const { user, session } = await authService.exchangeCodeForSession(code);

    if (jsonResponse) {
      return apiSuccess(
        {
          authenticated: true,
          user,
          session,
          redirectTo: safeNext,
        },
        200,
        undefined,
        { "Cache-Control": "no-store" }
      );
    }

    return NextResponse.redirect(new URL(safeNext, origin));
  } catch (error) {
    if (jsonResponse) {
      return handleRouteError(error);
    }

    const message =
      error instanceof Error
        ? error.message
        : "Authentication callback failed";
    return buildErrorRedirect(origin, "auth_callback_failed", message);
  }
}
