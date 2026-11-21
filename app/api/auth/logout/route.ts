import { authService } from "@/services/auth.service";
import { apiSuccess, handleRouteError } from "@/utils";

/**
 * POST /api/auth/logout
 * Signs out the active Supabase session and clears auth cookies.
 */
export async function POST() {
  try {
    await authService.signOut();
    return apiSuccess({ signedOut: true }, 200, undefined, {
      "Cache-Control": "no-store",
    });
  } catch (error) {
    return handleRouteError(error);
  }
}
