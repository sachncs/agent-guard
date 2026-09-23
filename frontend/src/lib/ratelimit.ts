/**
 * Pluggable fixed-window rate limiting for console mutation routes.
 *
 * Development defaults to an in-memory store. Production defaults to Redis
 * and refuses to fall back to process-local state. Set the Redis-compatible
 * REST endpoint (for example, Upstash) and token in production. Store errors
 * fail closed so an unavailable shared store cannot silently remove limits.
 */

import { isIP } from "node:net";
import { RedisRestClient } from "./redis_rest.ts";
import { validateSharedStoreUrl } from "./shared_store_url.ts";

const WINDOW_SECONDS = 60;
const WINDOW_MS = WINDOW_SECONDS * 1000;
const DEFAULT_MAX_BUCKETS = 10_000;

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
}

export interface RateLimitStore {
  consume(key: string, limitPerMinute: number): Promise<RateLimitResult>;
  healthCheck(): Promise<void>;
}

interface Bucket {
  count: number;
  windowStart: number;
}

export class MemoryRateLimitStore implements RateLimitStore {
  private readonly buckets = new Map<string, Bucket>();
  private nowMs: () => number;

  constructor(
    now: () => number = () => Date.now(),
    private readonly maxBuckets = DEFAULT_MAX_BUCKETS,
  ) {
    if (!Number.isSafeInteger(maxBuckets) || maxBuckets < 1) {
      throw new Error("maxBuckets must be a positive safe integer");
    }
    this.nowMs = now;
  }

  setClock(fn: () => number): void {
    this.nowMs = fn;
  }

  reset(): void {
    this.buckets.clear();
  }

  async consume(key: string, limitPerMinute: number): Promise<RateLimitResult> {
    if (!Number.isSafeInteger(limitPerMinute) || limitPerMinute < 1) {
      throw new Error("limitPerMinute must be a positive safe integer");
    }
    const now = this.nowMs();
    const bucket = this.buckets.get(key);
    if (!bucket || now - bucket.windowStart >= WINDOW_MS) {
      if (!bucket && this.buckets.size >= this.maxBuckets) {
        for (const [expiredKey, expired] of this.buckets) {
          if (now - expired.windowStart >= WINDOW_MS) this.buckets.delete(expiredKey);
        }
        // Never evict a live client's budget just to admit a new key. Fail
        // closed until a bucket expires, keeping development memory bounded.
        if (this.buckets.size >= this.maxBuckets) {
          return { allowed: false, remaining: 0 };
        }
      }
      this.buckets.set(key, { count: 1, windowStart: now });
      return { allowed: true, remaining: Math.max(0, limitPerMinute - 1) };
    }
    if (bucket.count >= limitPerMinute) return { allowed: false, remaining: 0 };
    bucket.count += 1;
    return { allowed: true, remaining: Math.max(0, limitPerMinute - bucket.count) };
  }

  async healthCheck(): Promise<void> {}
}

/** Redis-compatible REST store using an atomic INCR + EXPIRE script. */
export class RedisRateLimitStore implements RateLimitStore {
  private readonly redis: RedisRestClient;

  constructor(
    url: string,
    token: string,
    fetchImpl: typeof fetch = fetch,
    timeoutMs = 3_000,
    private readonly keyPrefix = "agentguard:ratelimit:",
  ) {
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(keyPrefix)) {
      throw new Error("rate-limit Redis key prefix must contain 1-128 safe characters");
    }
    this.redis = new RedisRestClient(url, token, fetchImpl, timeoutMs);
  }

  async consume(key: string, limitPerMinute: number): Promise<RateLimitResult> {
    const script = "local count=redis.call('INCR',KEYS[1]); if count==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]) end; return count";
    const result = await this.redis.command([
      "EVAL",
      script,
      "1",
      `${this.keyPrefix}${key}`,
      String(WINDOW_SECONDS),
    ]);
    if (typeof result !== "number" || !Number.isSafeInteger(result) || result < 1) {
      throw new Error("rate-limit store returned an invalid count");
    }
    return {
      allowed: result <= limitPerMinute,
      remaining: Math.max(0, limitPerMinute - result),
    };
  }

  async healthCheck(): Promise<void> {
    await this.redis.healthCheck();
  }
}

const memoryStore = new MemoryRateLimitStore();
let configuredStore: RateLimitStore | undefined;

export function configureRateLimitStore(store: RateLimitStore | undefined): void {
  configuredStore = store;
}

/** Check configuration and connectivity without consuming a rate-limit slot. */
export async function checkRateLimitStore(): Promise<void> {
  await activeStore().healthCheck();
}

function activeStore(): RateLimitStore {
  if (configuredStore) return configuredStore;
  const mode = process.env.AGENTGUARD_RATE_LIMIT_STORE ||
    (process.env.NODE_ENV === "production" ? "redis" : "memory");
  if (mode !== "memory" && mode !== "redis") {
    throw new Error("AGENTGUARD_RATE_LIMIT_STORE must be memory or redis");
  }
  if (mode === "memory") {
    if (process.env.NODE_ENV === "production") {
      throw new Error("production rate limiting requires AGENTGUARD_RATE_LIMIT_STORE=redis");
    }
    return memoryStore;
  }
  const url = process.env.AGENTGUARD_RATE_LIMIT_REDIS_URL;
  const token = process.env.AGENTGUARD_RATE_LIMIT_REDIS_TOKEN;
  const keyPrefix = process.env.AGENTGUARD_RATE_LIMIT_REDIS_PREFIX || "agentguard:ratelimit:";
  if (!url || !token) throw new Error("Redis rate limiting is not configured");
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(keyPrefix)) {
    throw new Error("AGENTGUARD_RATE_LIMIT_REDIS_PREFIX must contain 1-128 safe characters");
  }
  const issue = validateSharedStoreUrl(url);
  if (issue) throw new Error(`AGENTGUARD_RATE_LIMIT_REDIS_URL ${issue}`);
  configuredStore = new RedisRateLimitStore(url, token, fetch, 3_000, keyPrefix);
  return configuredStore;
}

/** Test hook: reset the development store and configured store selection. */
export function resetRateLimiter(): void {
  memoryStore.reset();
  configuredStore = undefined;
}

/** Test hook for deterministic memory-store windows. */
export function setClock(fn: () => number): void {
  memoryStore.setClock(fn);
}

/** Consume one slot. Store failures fail closed. */
export async function rateLimit(key: string, limitPerMinute: number): Promise<RateLimitResult> {
  try {
    return await activeStore().consume(key, limitPerMinute);
  } catch {
    return { allowed: false, remaining: 0 };
  }
}

/**
 * Use a forwarded client address only when configuration confirms the
 * reverse proxy overwrites X-Forwarded-For with exactly one validated IP.
 * Otherwise use the request host; never trust a client-supplied header by
 * default.
 */
export function clientKey(request: Request, trustProxyHeaders = false): string {
  if (trustProxyHeaders) {
    const forwardedFor = request.headers.get("x-forwarded-for")?.trim();
    if (forwardedFor && !forwardedFor.includes(",") && isIP(forwardedFor)) {
      const canonicalIp = isIP(forwardedFor) === 6
        ? new URL(`http://[${forwardedFor}]/`).hostname
        : forwardedFor;
      return `ip:${canonicalIp}`;
    }
  }
  return new URL(request.url).host || "local";
}
