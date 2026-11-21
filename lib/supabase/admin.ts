import { createClient } from "@supabase/supabase-js";
import type { Database } from "@/types";
import { getEnv } from "@/lib/env";

/**
 * Privileged Supabase client using the service role key.
 * ONLY use on trusted server paths (e.g. background audit logging or admin tasks).
 * Never expose this client or key to the browser.
 */
export function createSupabaseAdminClient() {
  const env = getEnv();
  if (!env.SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error(
      "SUPABASE_SERVICE_ROLE_KEY is required for admin Supabase operations"
    );
  }

  return createClient<Database>(
    env.NEXT_PUBLIC_SUPABASE_URL,
    env.SUPABASE_SERVICE_ROLE_KEY,
    {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    }
  );
}
