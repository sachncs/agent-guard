import type { SessionClaims } from "./session";
import { RedisRestClient } from "../redis_rest.ts";

/** Shared session state used to support revocation and horizontal scaling. */
export interface SessionStore {
  put(id: string, claims: SessionClaims, ttlSeconds: number): Promise<void>;
  get(id: string): Promise<SessionClaims | null>;
  delete(id: string): Promise<void>;
  healthCheck(): Promise<void>;
}

interface StoredSession {
  claims: SessionClaims;
  expiresAt: number;
}

const DEFAULT_MAX_MEMORY_SESSIONS = 10_000;

function sessionTtlMilliseconds(ttlSeconds: number): number {
  const ttlMs = ttlSeconds * 1_000;
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 1 || !Number.isSafeInteger(ttlMs)) {
    throw new Error("ttlSeconds must be a positive safe duration");
  }
  return ttlMs;
}

/** Development-only process-local store. It is not safe across replicas. */
export class MemorySessionStore implements SessionStore {
  private readonly sessions = new Map<string, StoredSession>();
  private now: () => number;
  private readonly maxSessions: number;

  constructor(
    now: () => number = () => Date.now(),
    maxSessions = DEFAULT_MAX_MEMORY_SESSIONS,
  ) {
    if (!Number.isSafeInteger(maxSessions) || maxSessions < 1) {
      throw new Error("maxSessions must be a positive safe integer");
    }
    this.now = now;
    this.maxSessions = maxSessions;
  }

  setClock(now: () => number): void {
    this.now = now;
  }

  reset(): void {
    this.sessions.clear();
  }

  async put(id: string, claims: SessionClaims, ttlSeconds: number): Promise<void> {
    const ttlMs = sessionTtlMilliseconds(ttlSeconds);
    const now = this.now();
    const expiresAt = now + ttlMs;
    if (!Number.isSafeInteger(expiresAt)) throw new Error("session expiration exceeds the clock range");
    if (!this.sessions.has(id) && this.sessions.size >= this.maxSessions) {
      for (const [expiredId, session] of this.sessions) {
        if (session.expiresAt <= now) this.sessions.delete(expiredId);
      }
      // Do not evict live sessions to admit new users; reject the new session
      // until capacity is available so memory stays bounded and revocation
      // state is never silently lost.
      if (this.sessions.size >= this.maxSessions) {
        throw new Error("memory session store capacity reached");
      }
    }
    this.sessions.set(id, { claims, expiresAt });
  }

  async get(id: string): Promise<SessionClaims | null> {
    const stored = this.sessions.get(id);
    if (!stored) return null;
    if (stored.expiresAt <= this.now()) {
      this.sessions.delete(id);
      return null;
    }
    return stored.claims;
  }

  async delete(id: string): Promise<void> {
    this.sessions.delete(id);
  }

  async healthCheck(): Promise<void> {}
}

/** Redis-compatible REST session store (for example, Upstash Redis). */
export class RedisSessionStore implements SessionStore {
  private readonly prefix: string;
  private readonly redis: RedisRestClient;

  constructor(
    url: string,
    token: string,
    fetchImpl: typeof fetch = fetch,
    prefix = "agentguard:session:",
    timeoutMs = 3_000,
  ) {
    this.prefix = prefix;
    this.redis = new RedisRestClient(url, token, fetchImpl, timeoutMs);
  }

  async put(id: string, claims: SessionClaims, ttlSeconds: number): Promise<void> {
    sessionTtlMilliseconds(ttlSeconds);
    const result = await this.redis.command([
      "SET",
      `${this.prefix}${id}`,
      JSON.stringify(claims),
      "EX",
      String(ttlSeconds),
    ]);
    if (result !== "OK") throw new Error("session store rejected session");
  }

  async get(id: string): Promise<SessionClaims | null> {
    const result = await this.redis.command(["GET", `${this.prefix}${id}`]);
    if (result === null) return null;
    if (typeof result !== "string") throw new Error("session store returned invalid data");
    const value = JSON.parse(result) as Partial<SessionClaims>;
    if (typeof value.sub !== "string" || typeof value.admin !== "boolean") {
      throw new Error("session store returned invalid claims");
    }
    return {
      sub: value.sub,
      admin: value.admin,
      email: typeof value.email === "string" ? value.email : undefined,
      name: typeof value.name === "string" ? value.name : undefined,
    };
  }

  async delete(id: string): Promise<void> {
    await this.redis.command(["DEL", `${this.prefix}${id}`]);
  }

  async healthCheck(): Promise<void> {
    await this.redis.healthCheck();
  }
}
