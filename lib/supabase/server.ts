import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";
import type { Database } from "@/types";
import { getEnv } from "@/lib/env";

/**
 * Creates a request-scoped Supabase client for Next.js 15 Server Components,
 * Server Actions, and Route Handlers. Automatically honors Supabase RLS
 * for the authenticated user session stored in cookies.
 */
export async function createSupabaseServerClient() {
  const cookieStore = await cookies();
  const env = getEnv();

  return createServerClient<Database>(
    env.NEXT_PUBLIC_SUPABASE_URL,
    env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    {
      cookies: {
        getAll() {
          return cookieStore.getAll();
        },
        setAll(cookiesToSet) {
          try {
            cookiesToSet.forEach(({ name, value, options }) => {
              cookieStore.set(name, value, options);
            });
          } catch {
            // `setAll` can throw when invoked from a read-only Server Component.
            // Session refresh is handled by `middleware.ts`.
          }
        },
      },
    }
  );
}
