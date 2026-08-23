/**
 * In-memory fixed-window rate limiter. Single-node only: counts reset on
 * restart and are not shared across replicas. Sufficient to blunt abuse
 * of expensive routes; swap for a shared store before horizontal scaling.
 */

const WINDOW_MS = 60_000;

interface Bucket {
  count: number;
  windowStart: number;
}

const buckets = new Map<string, Bucket>();

let nowMs: () => number = () => Date.now();

/** Test hook. */
export function setClock(fn: () => number): void {
  nowMs = fn;
}

/** Test hook: drop all buckets. */
export function resetRateLimiter(): void {
  buckets.clear();
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
}

export function rateLimit(key: string, limitPerMinute: number): RateLimitResult {
  const now = nowMs();
  const bucket = buckets.get(key);
  if (!bucket || now - bucket.windowStart >= WINDOW_MS) {
    buckets.set(key, { count: 1, windowStart: now });
    return { allowed: true, remaining: limitPerMinute - 1 };
  }
  if (bucket.count >= limitPerMinute) {
    return { allowed: false, remaining: 0 };
  }
  bucket.count += 1;
  return { allowed: true, remaining: limitPerMinute - bucket.count };
}

/** Best-effort client identity for rate limiting (first proxy hop). */
export function clientKey(request: Request): string {
  const fwd = request.headers.get("x-forwarded-for");
  if (fwd) return fwd.split(",")[0].trim();
  return "local";
}
