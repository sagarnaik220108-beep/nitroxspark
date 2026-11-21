import { authService } from "@/services/auth.service";
import { apiSuccess, handleRouteError } from "@/utils";

/**
 * GET /api/auth/session
 * Returns the active session state and synced `public.users` record
 * (`id`, `email`, `created_at`, `last_login`).
 */
export async function GET() {
  try {
    if (
      !process.env.NEXT_PUBLIC_SUPABASE_URL ||
      !process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
    ) {
      return apiSuccess(
        {
          authenticated: false,
          user: null,
          session: null,
        },
        200,
        undefined,
        { "Cache-Control": "no-store" }
      );
    }

    const sessionInfo = await authService.getSession();
    return apiSuccess(sessionInfo, 200, undefined, {
      "Cache-Control": "no-store",
    });
  } catch (error) {
    return handleRouteError(error);
  }
}
