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

/** Development-only process-local store. It is not safe across replicas. */
export class MemorySessionStore implements SessionStore {
  private readonly sessions = new Map<string, StoredSession>();
  private now: () => number;

  constructor(now: () => number = () => Date.now()) {
    this.now = now;
  }

  setClock(now: () => number): void {
    this.now = now;
  }

  reset(): void {
    this.sessions.clear();
  }

  async put(id: string, claims: SessionClaims, ttlSeconds: number): Promise<void> {
    this.sessions.set(id, { claims, expiresAt: this.now() + ttlSeconds * 1000 });
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
