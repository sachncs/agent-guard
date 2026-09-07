import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import {
  clientKey,
  rateLimit,
  resetRateLimiter,
  setClock,
} from "./ratelimit.ts";

describe("rate limiter", () => {
  beforeEach(() => {
    resetRateLimiter();
    setClock(() => 0);
  });

  it("allows up to the limit within a window", () => {
    for (let i = 0; i < 5; i++) {
      assert.equal(rateLimit("k", 5).allowed, true);
    }
    assert.equal(rateLimit("k", 5).allowed, false);
  });

  it("reports remaining budget", () => {
    assert.deepEqual(rateLimit("k", 3), { allowed: true, remaining: 2 });
    assert.deepEqual(rateLimit("k", 3), { allowed: true, remaining: 1 });
    assert.deepEqual(rateLimit("k", 3), { allowed: true, remaining: 0 });
    assert.deepEqual(rateLimit("k", 3), { allowed: false, remaining: 0 });
  });

  it("opens a fresh window after the boundary", () => {
    for (let i = 0; i < 2; i++) rateLimit("k", 2);
    assert.equal(rateLimit("k", 2).allowed, false);
    setClock(() => 60_001);
    assert.equal(rateLimit("k", 2).allowed, true);
  });

  it("isolates keys", () => {
    rateLimit("a", 1);
    assert.equal(rateLimit("a", 1).allowed, false);
    assert.equal(rateLimit("b", 1).allowed, true);
  });

  it("uses the first forwarded hop as the key", () => {
    const req = new Request("http://x/", {
      headers: { "x-forwarded-for": "203.0.113.7, 10.0.0.1" },
    });
    assert.equal(clientKey(req), "203.0.113.7");
  });
});
