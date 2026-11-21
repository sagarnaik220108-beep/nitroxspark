import type { NextRequest } from "next/server";
import { updateSupabaseSession } from "@/lib/supabase";
import { apiError } from "@/utils/api-response";

const PROTECTED_API_PREFIXES = [
  "/api/dashboard",
  "/api/project",
  "/api/scan",
  "/api/scans",
  "/api/report",
  "/api/reports",
  "/api/timeline",
  "/api/rules",
  "/api/simulations",
  "/api/vulnerabilities",
] as const;

const PUBLIC_PATHS = [
  "/api/auth",
  "/auth/callback",
  "/api/health",
  "/api/reports/generate",
] as const;

function matchesPrefix(pathname: string, prefixes: readonly string[]): boolean {
  return prefixes.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`)
  );
}

/**
 * Next.js App Router middleware:
 * - Refreshes the Supabase auth session cookies transparently.
 * - Allows public routes (`/api/auth/*`, `/auth/callback`, `/api/health`, etc.).
 * - Enforces authentication on protected API routes, returning a clean 401 JSON response.
 */
export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  const { response, user } = await updateSupabaseSession(request);

  if (matchesPrefix(pathname, PUBLIC_PATHS)) {
    return response;
  }

  if (matchesPrefix(pathname, PROTECTED_API_PREFIXES) && !user) {
    return apiError(
      "UNAUTHORIZED",
      "Valid authenticated session is required to access this resource",
      401,
      undefined,
      { "Cache-Control": "no-store" }
    );
  }

  return response;
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)",
  ],
};
