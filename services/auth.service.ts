import type { SupabaseClient, User } from "@supabase/supabase-js";
import type { ProfileRow } from "@/types";
import { getEnv } from "@/lib/env";
import { createSupabaseServerClient } from "@/lib/supabase";
import {
  InternalServerError,
  UnauthorizedError,
  ValidationError,
} from "@/utils";

export type SupabaseServerClient = Awaited<
  ReturnType<typeof createSupabaseServerClient>
>;

export interface AuthenticatedContext {
  user: User;
  supabase: SupabaseServerClient;
}

export type UserRecord = {
  id: string;
  email: string;
  created_at: string;
  last_login: string;
};

export interface SessionMetadata {
  expiresAt: number | null;
  provider: string | null;
}

export interface SessionInfo {
  authenticated: boolean;
  user: UserRecord | null;
  session: SessionMetadata | null;
}

export interface OAuthExchangeResult {
  user: UserRecord;
  session: SessionMetadata;
}

/**
 * Local typed schema view for `public.users` so AuthService remains strongly
 * typed against migration `001_users_auth.sql` without mutating shared schema files.
 */
interface UsersTableSchema {
  public: {
    Tables: {
      users: {
        Row: UserRecord;
        Insert: {
          id: string;
          email: string;
          created_at?: string;
          last_login?: string;
        };
        Update: {
          email?: string;
          last_login?: string;
        };
        Relationships: [];
      };
    };
    Views: Record<string, never>;
    Functions: Record<string, never>;
    Enums: Record<string, never>;
    CompositeTypes: Record<string, never>;
  };
}

function getUsersClient(
  supabase: SupabaseServerClient
): SupabaseClient<UsersTableSchema> {
  return supabase as unknown as SupabaseClient<UsersTableSchema>;
}

function resolveProvider(user: User): string | null {
  const provider = user.app_metadata?.provider;
  return typeof provider === "string" ? provider : null;
}

/**
 * Sanitizes a post-login redirect path to prevent open-redirect vulnerabilities.
 */
export function sanitizeRedirectPath(
  nextPath: string | null | undefined,
  fallback = "/dashboard"
): string {
  if (!nextPath) return fallback;
  const trimmed = nextPath.trim();
  if (trimmed.startsWith("/") && !trimmed.startsWith("//")) {
    return trimmed;
  }
  return fallback;
}

/**
 * AuthService encapsulates Supabase Google OAuth session handling,
 * user authentication guards, `public.users` login synchronization, and sign-out.
 */
export class AuthService {
  /**
   * Verifies the active Supabase session using `auth.getUser()` (server-verified JWT)
   * and returns the authenticated user alongside a request-scoped Supabase client.
   */
  public async requireAuthenticatedUser(): Promise<AuthenticatedContext> {
    const supabase = await createSupabaseServerClient();
    const {
      data: { user },
      error,
    } = await supabase.auth.getUser();

    if (error || !user) {
      throw new UnauthorizedError("Valid authenticated session is required");
    }

    return { user, supabase };
  }

  /**
   * Upserts the authenticated user's record in `public.users` and records
   * the current UTC timestamp in `last_login`.
   */
  public async syncUserLogin(
    supabase: SupabaseServerClient,
    user: User
  ): Promise<UserRecord> {
    const nowIso = new Date().toISOString();
    const usersClient = getUsersClient(supabase);

    const { data, error } = await usersClient
      .from("users")
      .upsert(
        {
          id: user.id,
          email: user.email ?? "",
          last_login: nowIso,
        },
        { onConflict: "id" }
      )
      .select("id, email, created_at, last_login")
      .single();

    if (error || !data) {
      throw new InternalServerError(
        "Failed to synchronize user login record",
        error?.message
      );
    }

    return data;
  }

  /**
   * Reads the user's record from `public.users`, lazily synchronizing it if missing.
   */
  public async getUserRecord(
    supabase: SupabaseServerClient,
    user: User
  ): Promise<UserRecord> {
    const usersClient = getUsersClient(supabase);

    const { data, error } = await usersClient
      .from("users")
      .select("id, email, created_at, last_login")
      .eq("id", user.id)
      .maybeSingle();

    if (error) {
      throw new InternalServerError(
        "Failed to fetch user record",
        error.message
      );
    }

    if (data) {
      return data;
    }

    return this.syncUserLogin(supabase, user);
  }

  /**
   * Returns the current authentication state along with the synced `public.users`
   * record (`id`, `email`, `created_at`, `last_login`).
   */
  public async getSession(): Promise<SessionInfo> {
    const supabase = await createSupabaseServerClient();
    const {
      data: { user },
      error,
    } = await supabase.auth.getUser();

    if (error || !user) {
      return {
        authenticated: false,
        user: null,
        session: null,
      };
    }

    const [{ data: sessionData }, userRecord] = await Promise.all([
      supabase.auth.getSession(),
      this.getUserRecord(supabase, user),
    ]);

    return {
      authenticated: true,
      user: userRecord,
      session: {
        expiresAt: sessionData.session?.expires_at ?? null,
        provider: resolveProvider(user),
      },
    };
  }

  /**
   * Returns the authenticated user's profile row from `public.profiles`.
   */
  public async getCurrentProfile(): Promise<{
    user: { id: string; email: string | undefined };
    profile: ProfileRow | null;
  }> {
    const { user, supabase } = await this.requireAuthenticatedUser();

    const { data, error } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", user.id)
      .maybeSingle();

    if (error) {
      throw new InternalServerError(
        "Failed to fetch user profile",
        error.message
      );
    }

    return {
      user: { id: user.id, email: user.email },
      profile: data,
    };
  }

  /**
   * Generates a Supabase Google OAuth redirect URL for initiating sign-in.
   */
  public async createGoogleOAuthUrl(nextPath = "/dashboard"): Promise<string> {
    const supabase = await createSupabaseServerClient();
    const env = getEnv();

    const safeNext = sanitizeRedirectPath(nextPath, "/dashboard");
    const redirectTo = `${env.NEXT_PUBLIC_APP_URL}/auth/callback?next=${encodeURIComponent(safeNext)}`;

    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: "google",
      options: {
        redirectTo,
        queryParams: {
          access_type: "offline",
          prompt: "consent",
        },
      },
    });

    if (error || !data.url) {
      throw new InternalServerError(
        "Failed to initialize Google OAuth sign-in",
        error?.message
      );
    }

    return data.url;
  }

  /**
   * Exchanges a Google OAuth authorization code for a Supabase session
   * and updates `last_login` in `public.users`.
   */
  public async exchangeCodeForSession(
    code: string
  ): Promise<OAuthExchangeResult> {
    const trimmedCode = code.trim();
    if (!trimmedCode) {
      throw new ValidationError("Missing OAuth authorization code");
    }

    const supabase = await createSupabaseServerClient();
    const { data, error } =
      await supabase.auth.exchangeCodeForSession(trimmedCode);

    if (error || !data.user) {
      throw new UnauthorizedError(
        "Invalid or expired OAuth authorization code"
      );
    }

    const syncedUser = await this.syncUserLogin(supabase, data.user);

    return {
      user: syncedUser,
      session: {
        expiresAt: data.session?.expires_at ?? null,
        provider: resolveProvider(data.user),
      },
    };
  }

  /**
   * Signs out the current user session and clears auth cookies.
   */
  public async signOut(): Promise<void> {
    const supabase = await createSupabaseServerClient();
    const { error } = await supabase.auth.signOut();
    if (error) {
      throw new InternalServerError("Failed to sign out", error.message);
    }
  }
}

export const authService = new AuthService();
