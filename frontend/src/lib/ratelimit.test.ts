import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import {
  clientKey,
  MemoryRateLimitStore,
  rateLimit,
  RedisRateLimitStore,
  resetRateLimiter,
  setClock,
} from "./ratelimit.ts";

describe("rate limiter", () => {
  beforeEach(() => {
    process.env.AGENTGUARD_RATE_LIMIT_STORE = "memory";
    resetRateLimiter();
    setClock(() => 0);
  });

  it("bounds development memory and does not evict active budgets", async () => {
    let now = 0;
    const store = new MemoryRateLimitStore(() => now, 2);
    assert.deepEqual(await store.consume("a", 1), { allowed: true, remaining: 0 });
    assert.deepEqual(await store.consume("b", 1), { allowed: true, remaining: 0 });
    assert.deepEqual(await store.consume("c", 1), { allowed: false, remaining: 0 });
    assert.deepEqual(await store.consume("a", 1), { allowed: false, remaining: 0 });

    now = 60_000;
    assert.deepEqual(await store.consume("c", 1), { allowed: true, remaining: 0 });
    assert.deepEqual(await store.consume("a", 1), { allowed: true, remaining: 0 });
  });

  it("rejects invalid limits and bucket capacities", async () => {
    assert.throws(() => new MemoryRateLimitStore(() => 0, 0), /maxBuckets/);
    const store = new MemoryRateLimitStore(() => 0, 1);
    await assert.rejects(store.consume("key", 0), /limitPerMinute/);
    await assert.rejects(store.consume("key", 1.5), /limitPerMinute/);
  });

  it("allows up to the limit within a window", async () => {
    for (let i = 0; i < 5; i++) {
      assert.equal((await rateLimit("k", 5)).allowed, true);
    }
    assert.equal((await rateLimit("k", 5)).allowed, false);
  });

  it("reports remaining budget", async () => {
    assert.deepEqual((await rateLimit("k", 3)), { allowed: true, remaining: 2 });
    assert.deepEqual((await rateLimit("k", 3)), { allowed: true, remaining: 1 });
    assert.deepEqual((await rateLimit("k", 3)), { allowed: true, remaining: 0 });
    assert.deepEqual((await rateLimit("k", 3)), { allowed: false, remaining: 0 });
  });

  it("opens a fresh window after the boundary", async () => {
    for (let i = 0; i < 2; i++) await rateLimit("k", 2);
    assert.equal((await rateLimit("k", 2)).allowed, false);
    setClock(() => 60_001);
    assert.equal((await rateLimit("k", 2)).allowed, true);
  });

  it("isolates keys", async () => {
    await rateLimit("a", 1);
    assert.equal((await rateLimit("a", 1)).allowed, false);
    assert.equal((await rateLimit("b", 1)).allowed, true);
  });

  it("does not trust spoofable forwarded headers", () => {
    const req = new Request("http://x/", {
      headers: { "x-forwarded-for": "203.0.113.7, 10.0.0.1" },
    });
    assert.equal(clientKey(req), "x");
  });

  it("uses a single validated proxy address only when proxy trust is enabled", () => {
    const forwarded = new Request("https://console.example/api", {
      headers: { "x-forwarded-for": "203.0.113.7" },
    });
    assert.equal(clientKey(forwarded), "console.example");
    assert.equal(clientKey(forwarded, true), "ip:203.0.113.7");

    const ipv6 = new Request("https://console.example/api", {
      headers: { "x-forwarded-for": "2001:0db8:0:0:0:0:0:1" },
    });
    assert.equal(clientKey(ipv6, true), "ip:[2001:db8::1]");
  });

  it("rejects forwarded chains and malformed addresses even with proxy trust", () => {
    const chained = new Request("https://console.example/api", {
      headers: { "x-forwarded-for": "203.0.113.7, 10.0.0.1" },
    });
    assert.equal(clientKey(chained, true), "console.example");
    const malformed = new Request("https://console.example/api", {
      headers: { "x-forwarded-for": "attacker-controlled" },
    });
    assert.equal(clientKey(malformed, true), "console.example");
  });

  it("uses an atomic Redis-compatible request", async () => {
    let request: Request | undefined;
    let redirect: RequestRedirect | undefined;
    const store = new RedisRateLimitStore("https://redis.example", "secret", async (_url, init) => {
      request = new Request(String(_url), init);
      redirect = init?.redirect;
      return new Response(JSON.stringify({ result: 2 }), { status: 200 });
    });
    assert.deepEqual(await store.consume("delegate:x", 5), { allowed: true, remaining: 3 });
    assert.equal(request?.headers.get("authorization"), "Bearer secret");
    assert.equal(redirect, "error", "credential-bearing store requests must reject redirects");
    assert.match(await request!.text(), /EVAL/);
  });

  it("checks Redis connectivity without consuming a rate-limit slot", async () => {
    let body = "";
    let redirect: RequestRedirect | undefined;
    const store = new RedisRateLimitStore("https://redis.example", "secret", async (_url, init) => {
      body = String(init?.body);
      redirect = init?.redirect;
      return new Response(JSON.stringify({ result: "PONG" }), { status: 200 });
    });
    await store.healthCheck();
    assert.deepEqual(JSON.parse(body), ["PING"]);
    assert.equal(redirect, "error");
  });

  it("fails closed when the shared store is unavailable", async () => {
    const store = new RedisRateLimitStore("https://redis.example", "secret", async () => {
      throw new Error("offline");
    });
    assert.deepEqual(await store.consume("k", 5).catch(() => ({ allowed: false, remaining: 0 })), { allowed: false, remaining: 0 });
  });

  it("does not fall back to memory in production", async () => {
    const env = process.env as Record<string, string | undefined>;
    const previousNodeEnv = process.env.NODE_ENV;
    const previousMode = process.env.AGENTGUARD_RATE_LIMIT_STORE;
    delete process.env.AGENTGUARD_RATE_LIMIT_STORE;
    delete process.env.AGENTGUARD_RATE_LIMIT_REDIS_URL;
    delete process.env.AGENTGUARD_RATE_LIMIT_REDIS_TOKEN;
    env.NODE_ENV = "production";
    resetRateLimiter();
    assert.deepEqual(await rateLimit("production", 5), { allowed: false, remaining: 0 });
    if (previousNodeEnv === undefined) delete env.NODE_ENV;
    else env.NODE_ENV = previousNodeEnv;
    if (previousMode === undefined) delete process.env.AGENTGUARD_RATE_LIMIT_STORE;
    else process.env.AGENTGUARD_RATE_LIMIT_STORE = previousMode;
    resetRateLimiter();
  });

  it("fails closed without sending credentials to a non-HTTPS production endpoint", async () => {
    const env = process.env as Record<string, string | undefined>;
    const previous = {
      nodeEnv: env.NODE_ENV,
      store: env.AGENTGUARD_RATE_LIMIT_STORE,
      url: env.AGENTGUARD_RATE_LIMIT_REDIS_URL,
      token: env.AGENTGUARD_RATE_LIMIT_REDIS_TOKEN,
    };
    env.NODE_ENV = "production";
    env.AGENTGUARD_RATE_LIMIT_STORE = "redis";
    env.AGENTGUARD_RATE_LIMIT_REDIS_URL = "http://redis.example";
    env.AGENTGUARD_RATE_LIMIT_REDIS_TOKEN = "secret";
    resetRateLimiter();
    try {
      assert.deepEqual(await rateLimit("unsafe", 5), { allowed: false, remaining: 0 });
    } finally {
      if (previous.nodeEnv === undefined) delete env.NODE_ENV;
      else env.NODE_ENV = previous.nodeEnv;
      for (const [key, value] of [
        ["AGENTGUARD_RATE_LIMIT_STORE", previous.store],
        ["AGENTGUARD_RATE_LIMIT_REDIS_URL", previous.url],
        ["AGENTGUARD_RATE_LIMIT_REDIS_TOKEN", previous.token],
      ] as const) {
        if (value === undefined) delete env[key];
        else env[key] = value;
      }
      resetRateLimiter();
    }
  });

  it("rejects an explicit memory rate-limit store in production", async () => {
    const env = process.env as Record<string, string | undefined>;
    const previousNodeEnv = env.NODE_ENV;
    const previousStore = env.AGENTGUARD_RATE_LIMIT_STORE;
    env.NODE_ENV = "production";
    env.AGENTGUARD_RATE_LIMIT_STORE = "memory";
    resetRateLimiter();

    try {
      assert.deepEqual(await rateLimit("explicit-memory", 5), {
        allowed: false,
        remaining: 0,
      });
    } finally {
      if (previousNodeEnv === undefined) delete env.NODE_ENV;
      else env.NODE_ENV = previousNodeEnv;
      if (previousStore === undefined) delete env.AGENTGUARD_RATE_LIMIT_STORE;
      else env.AGENTGUARD_RATE_LIMIT_STORE = previousStore;
      resetRateLimiter();
    }
  });
});
