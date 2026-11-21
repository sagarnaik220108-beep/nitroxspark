import { createHash } from "node:crypto";

export interface CacheEntryOptions {
  /** Time-to-live in milliseconds. Defaults to the cache instance default. */
  ttlMs?: number;
  /** Optional tags for grouped invalidation (e.g., `["user:123", "scans"]`). */
  tags?: readonly string[];
}

export interface TTLCacheOptions {
  /** Maximum number of entries retained before LRU eviction. Defaults to 500. */
  maxEntries?: number;
  /** Default entry TTL in milliseconds. Defaults to 60_000 (1 minute). */
  defaultTtlMs?: number;
}

export interface CacheStats {
  size: number;
  maxEntries: number;
  hits: number;
  misses: number;
  evictions: number;
  expirations: number;
  tagCount: number;
}

interface InternalEntry<T> {
  value: T;
  expiresAt: number;
  tags: ReadonlySet<string>;
}

/**
 * Memory-safe, LRU-bounded in-memory TTL cache with tag-based invalidation
 * and in-flight promise coalescing to prevent cache stampedes.
 */
export class TTLCache<T = unknown> {
  private readonly store = new Map<string, InternalEntry<T>>();
  private readonly tagIndex = new Map<string, Set<string>>();
  private readonly inFlight = new Map<string, Promise<T>>();
  private readonly maxEntries: number;
  private readonly defaultTtlMs: number;

  private hits = 0;
  private misses = 0;
  private evictions = 0;
  private expirations = 0;

  constructor(options: TTLCacheOptions = {}) {
    this.maxEntries = Math.max(1, Math.floor(options.maxEntries ?? 500));
    this.defaultTtlMs = Math.max(1, Math.floor(options.defaultTtlMs ?? 60_000));
  }

  public get size(): number {
    return this.store.size;
  }

  /**
   * Retrieves a non-expired value and refreshes its LRU position.
   */
  public get(key: string): T | undefined {
    const entry = this.store.get(key);
    if (!entry) {
      this.misses += 1;
      return undefined;
    }

    if (Date.now() >= entry.expiresAt) {
      this.removeKey(key);
      this.expirations += 1;
      this.misses += 1;
      return undefined;
    }

    // Refresh LRU order by re-inserting at the tail of the Map
    this.store.delete(key);
    this.store.set(key, entry);
    this.hits += 1;
    return entry.value;
  }

  /**
   * Checks whether a non-expired key currently exists in the cache.
   */
  public has(key: string): boolean {
    const entry = this.store.get(key);
    if (!entry) return false;

    if (Date.now() >= entry.expiresAt) {
      this.removeKey(key);
      this.expirations += 1;
      return false;
    }

    return true;
  }

  /**
   * Stores a value with an optional TTL and invalidation tags.
   * Evicts the least-recently-used entry when capacity is reached.
   */
  public set(key: string, value: T, options: CacheEntryOptions = {}): void {
    const ttlMs = options.ttlMs ?? this.defaultTtlMs;
    if (ttlMs <= 0) {
      this.removeKey(key);
      return;
    }

    if (this.store.has(key)) {
      this.removeKey(key);
    } else if (this.store.size >= this.maxEntries) {
      this.pruneExpired();
      while (this.store.size >= this.maxEntries) {
        const oldestKey = this.store.keys().next().value;
        if (oldestKey === undefined) break;
        this.removeKey(oldestKey);
        this.evictions += 1;
      }
    }

    const tags = new Set(options.tags ?? []);
    const entry: InternalEntry<T> = {
      value,
      expiresAt: Date.now() + ttlMs,
      tags,
    };

    this.store.set(key, entry);
    for (const tag of tags) {
      let keys = this.tagIndex.get(tag);
      if (!keys) {
        keys = new Set<string>();
        this.tagIndex.set(tag, keys);
      }
      keys.add(key);
    }
  }

  /**
   * Returns a cached value or executes `factory`, caching its result.
   * Concurrent calls for the same key share a single in-flight promise.
   */
  public async getOrSet(
    key: string,
    factory: () => Promise<T> | T,
    options: CacheEntryOptions = {}
  ): Promise<T> {
    const cached = this.get(key);
    if (cached !== undefined) {
      return cached;
    }

    const pending = this.inFlight.get(key);
    if (pending) {
      return pending;
    }

    const promise = Promise.resolve()
      .then(() => factory())
      .then((value) => {
        this.set(key, value, options);
        return value;
      })
      .finally(() => {
        this.inFlight.delete(key);
      });

    this.inFlight.set(key, promise);
    return promise;
  }

  /**
   * Removes a single key from the cache.
   */
  public delete(key: string): boolean {
    return this.removeKey(key);
  }

  /**
   * Invalidates all cached entries associated with the given tag.
   * Returns the number of entries removed.
   */
  public invalidateByTag(tag: string): number {
    const keys = this.tagIndex.get(tag);
    if (!keys || keys.size === 0) {
      return 0;
    }

    let removed = 0;
    for (const key of Array.from(keys)) {
      if (this.removeKey(key)) {
        removed += 1;
      }
    }
    this.tagIndex.delete(tag);
    return removed;
  }

  /**
   * Invalidates all cached entries matching any of the provided tags.
   */
  public invalidateByTags(tags: readonly string[]): number {
    let removed = 0;
    for (const tag of tags) {
      removed += this.invalidateByTag(tag);
    }
    return removed;
  }

  /**
   * Sweeps and removes all expired entries. Returns the number purged.
   */
  public pruneExpired(): number {
    const now = Date.now();
    let purged = 0;

    for (const [key, entry] of this.store.entries()) {
      if (now >= entry.expiresAt) {
        this.removeKey(key);
        this.expirations += 1;
        purged += 1;
      }
    }

    return purged;
  }

  /**
   * Clears all entries, tags, and in-flight trackers.
   */
  public clear(): void {
    this.store.clear();
    this.tagIndex.clear();
    this.inFlight.clear();
  }

  /**
   * Returns runtime telemetry for observability and health checks.
   */
  public stats(): CacheStats {
    return {
      size: this.store.size,
      maxEntries: this.maxEntries,
      hits: this.hits,
      misses: this.misses,
      evictions: this.evictions,
      expirations: this.expirations,
      tagCount: this.tagIndex.size,
    };
  }

  private removeKey(key: string): boolean {
    const entry = this.store.get(key);
    if (!entry) return false;

    this.store.delete(key);
    for (const tag of entry.tags) {
      const keys = this.tagIndex.get(tag);
      if (!keys) continue;
      keys.delete(key);
      if (keys.size === 0) {
        this.tagIndex.delete(tag);
      }
    }

    return true;
  }
}

/**
 * Shared process-local cache instance for deterministic metadata, rule listings,
 * and short-lived read-through responses.
 */
export const defaultCache = new TTLCache<unknown>({
  maxEntries: 500,
  defaultTtlMs: 60_000,
});

export interface HttpCacheHeaderOptions {
  /** Disables all client and CDN caching (`no-store`). Takes precedence. */
  noStore?: boolean;
  /** Visibility directive (`private` for user-scoped data, `public` for shared data). */
  visibility?: "public" | "private";
  /** Browser max-age in seconds. */
  maxAgeSeconds?: number;
  /** Shared CDN (Vercel Edge) s-maxage in seconds. */
  sMaxAgeSeconds?: number;
  /** Stale-while-revalidate window in seconds. */
  staleWhileRevalidateSeconds?: number;
  /** Appends `must-revalidate`. */
  mustRevalidate?: boolean;
  /** Optional weak or strong ETag header value. */
  etag?: string;
  /** Optional `Vary` header fields (e.g., `["Authorization", "Accept-Encoding"]`). */
  vary?: readonly string[];
}

/**
 * Computes a deterministic weak ETag (`W/"<sha256-prefix>"`) for JSON or text payloads.
 */
export function computeWeakETag(payload: unknown): string {
  const serialized =
    typeof payload === "string" ? payload : JSON.stringify(payload);
  const digest = createHash("sha256")
    .update(serialized)
    .digest("hex")
    .slice(0, 24);
  return `W/"${digest}"`;
}

/**
 * Evaluates an incoming `If-None-Match` header against a computed ETag.
 */
export function isETagFresh(requestHeaders: Headers, etag: string): boolean {
  const ifNoneMatch = requestHeaders.get("if-none-match");
  if (!ifNoneMatch) return false;
  if (ifNoneMatch.trim() === "*") return true;

  const normalizedTarget = etag.replace(/^W\//, "");
  return ifNoneMatch
    .split(",")
    .map((candidate) => candidate.trim().replace(/^W\//, ""))
    .includes(normalizedTarget);
}

/**
 * Builds standardized HTTP caching headers (`Cache-Control`, `ETag`, `Vary`)
 * compatible with Vercel Edge CDN and browsers.
 */
export function buildCacheHeaders(
  options: HttpCacheHeaderOptions = {}
): Record<string, string> {
  const headers: Record<string, string> = {};

  if (options.noStore) {
    headers["Cache-Control"] = "no-store, max-age=0";
  } else {
    const directives: string[] = [options.visibility ?? "private"];

    if (options.maxAgeSeconds !== undefined) {
      directives.push(`max-age=${Math.max(0, Math.floor(options.maxAgeSeconds))}`);
    }
    if (options.sMaxAgeSeconds !== undefined) {
      directives.push(
        `s-maxage=${Math.max(0, Math.floor(options.sMaxAgeSeconds))}`
      );
    }
    if (options.staleWhileRevalidateSeconds !== undefined) {
      directives.push(
        `stale-while-revalidate=${Math.max(0, Math.floor(options.staleWhileRevalidateSeconds))}`
      );
    }
    if (options.mustRevalidate) {
      directives.push("must-revalidate");
    }

    headers["Cache-Control"] = directives.join(", ");
  }

  if (options.etag) {
    headers["ETag"] = options.etag;
  }

  if (options.vary && options.vary.length > 0) {
    headers["Vary"] = Array.from(new Set(options.vary)).join(", ");
  }

  return headers;
}
