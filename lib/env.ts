import { z } from "zod";

const serverEnvSchema = z.object({
  NEXT_PUBLIC_APP_URL: z.string().url().default("http://localhost:3000"),
  NEXT_PUBLIC_SUPABASE_URL: z.string().url("NEXT_PUBLIC_SUPABASE_URL must be a valid URL"),
  NEXT_PUBLIC_SUPABASE_ANON_KEY: z.string().min(1, "NEXT_PUBLIC_SUPABASE_ANON_KEY is required"),
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(1).optional(),
  AI_PROVIDER: z.enum(["none", "openai", "gemini", "anthropic"]).default("none"),
  AI_API_KEY: z.string().optional(),
  AI_MODEL: z.string().optional(),
  SCAN_RATE_LIMIT_MAX: z.coerce.number().int().positive().default(30),
  SCAN_RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(60_000),
  MAX_CODE_SIZE_BYTES: z.coerce.number().int().positive().default(262_144),
});

export type ServerEnv = z.infer<typeof serverEnvSchema>;

let cachedEnv: ServerEnv | null = null;

/**
 * Lazily parses and caches server environment variables so Next.js build-time
 * static analysis does not fail when runtime secrets are injected on Vercel.
 */
export function getEnv(): ServerEnv {
  if (cachedEnv) return cachedEnv;

  const parsed = serverEnvSchema.safeParse({
    NEXT_PUBLIC_APP_URL: process.env.NEXT_PUBLIC_APP_URL,
    NEXT_PUBLIC_SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL,
    NEXT_PUBLIC_SUPABASE_ANON_KEY: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    SUPABASE_SERVICE_ROLE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY,
    AI_PROVIDER: process.env.AI_PROVIDER,
    AI_API_KEY: process.env.AI_API_KEY,
    AI_MODEL: process.env.AI_MODEL,
    SCAN_RATE_LIMIT_MAX: process.env.SCAN_RATE_LIMIT_MAX,
    SCAN_RATE_LIMIT_WINDOW_MS: process.env.SCAN_RATE_LIMIT_WINDOW_MS,
    MAX_CODE_SIZE_BYTES: process.env.MAX_CODE_SIZE_BYTES,
  });

  if (!parsed.success) {
    throw new Error(
      `Invalid environment configuration: ${JSON.stringify(parsed.error.flatten().fieldErrors)}`
    );
  }

  cachedEnv = parsed.data;
  return cachedEnv;
}
