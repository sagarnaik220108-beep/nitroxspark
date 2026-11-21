import type { NextRequest } from "next/server";
import { z } from "zod";
import { authService, sanitizeRedirectPath } from "@/services/auth.service";
import { apiSuccess, handleRouteError, ValidationError } from "@/utils";

const googleAuthBodySchema = z
  .object({
    next: z.string().max(512).optional(),
  })
  .strict();

async function initiateGoogleOAuth(nextPath: string) {
  const url = await authService.createGoogleOAuthUrl(nextPath);
  return apiSuccess(
    {
      url,
      provider: "google" as const,
    },
    200,
    undefined,
    { "Cache-Control": "no-store" }
  );
}

/**
 * GET /api/auth/google
 * Initiates Supabase Google OAuth and returns `{ url, provider: "google" }`.
 */
export async function GET(request: NextRequest) {
  try {
    const nextPath = sanitizeRedirectPath(
      request.nextUrl.searchParams.get("next"),
      "/dashboard"
    );
    return await initiateGoogleOAuth(nextPath);
  } catch (error) {
    return handleRouteError(error);
  }
}

/**
 * POST /api/auth/google
 * Initiates Supabase Google OAuth (accepting an optional `{ next }` JSON body)
 * and returns `{ url, provider: "google" }`.
 */
export async function POST(request: NextRequest) {
  try {
    let nextPath = "/dashboard";
    const rawBody = await request.text();

    if (rawBody.trim().length > 0) {
      let parsedJson: unknown;
      try {
        parsedJson = JSON.parse(rawBody);
      } catch {
        throw new ValidationError("Request body must be valid JSON");
      }

      const parsed = googleAuthBodySchema.parse(parsedJson);
      nextPath = sanitizeRedirectPath(parsed.next, "/dashboard");
    }

    return await initiateGoogleOAuth(nextPath);
  } catch (error) {
    return handleRouteError(error);
  }
}
