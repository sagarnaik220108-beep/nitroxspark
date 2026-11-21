import { RateLimitError } from "@/utils";

interface RateLimitBucket {
  timestamps: number[];
}

const buckets = new Map<string, RateLimitBucket>();

export interface RateLimitConfig {
  maxRequests: number;
  windowMs: number;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAtMs: number;
}

/**
 * In-memory sliding-window rate limiter suitable for single-instance / edge-local throttling.
 * For distributed multi-region enforcement on Vercel, swap the backing store for Upstash Redis.
 */
export function checkRateLimit(
  key: string,
  config: RateLimitConfig
): RateLimitResult {
  const now = Date.now();
  const windowStart = now - config.windowMs;
  const bucket = buckets.get(key) ?? { timestamps: [] };

  bucket.timestamps = bucket.timestamps.filter((ts) => ts > windowStart);

  if (bucket.timestamps.length >= config.maxRequests) {
    const oldest = bucket.timestamps[0] ?? now;
    const resetAtMs = oldest + config.windowMs;
    buckets.set(key, bucket);
    return {
      allowed: false,
      remaining: 0,
      resetAtMs,
    };
  }

  bucket.timestamps.push(now);
  buckets.set(key, bucket);

  return {
    allowed: true,
    remaining: Math.max(0, config.maxRequests - bucket.timestamps.length),
    resetAtMs: now + config.windowMs,
  };
}

/**
 * Enforces a rate limit and throws a typed RateLimitError when exceeded.
 */
export function enforceRateLimit(key: string, config: RateLimitConfig): void {
  const result = checkRateLimit(key, config);
  if (!result.allowed) {
    const retryAfterSeconds = Math.max(
      1,
      Math.ceil((result.resetAtMs - Date.now()) / 1000)
    );
    throw new RateLimitError(
      `Rate limit exceeded. Retry in ${retryAfterSeconds} second(s).`,
      retryAfterSeconds
    );
  }
}
