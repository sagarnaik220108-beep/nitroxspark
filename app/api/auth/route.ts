import { authService } from "@/services/auth.service";
import { apiSuccess, handleRouteError } from "@/utils";

const AUTH_ENDPOINTS = {
  googleOAuth: "/api/auth/google",
  session: "/api/auth/session",
  logout: "/api/auth/logout",
  callback: "/auth/callback",
} as const;

/**
 * GET /api/auth
 * Returns the active authentication session status along with available auth endpoints.
 */
export async function GET() {
  try {
    const sessionInfo = await authService.getSession();
    return apiSuccess(
      {
        ...sessionInfo,
        endpoints: AUTH_ENDPOINTS,
      },
      200,
      undefined,
      { "Cache-Control": "no-store" }
    );
  } catch (error) {
    return handleRouteError(error);
  }
}

/**
 * DELETE /api/auth
 * RESTful logout endpoint: terminates the active Supabase session and clears auth cookies.
 */
export async function DELETE() {
  try {
    await authService.signOut();
    return apiSuccess({ signedOut: true }, 200, undefined, {
      "Cache-Control": "no-store",
    });
  } catch (error) {
    return handleRouteError(error);
  }
}
