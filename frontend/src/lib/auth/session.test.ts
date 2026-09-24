import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  SESSION_COOKIE,
  parseCookieHeader,
  revokeSession,
  serializeSetCookie,
  signSession,
  verifySession,
} from "./session.ts";
import { MemorySessionStore } from "./session_store.ts";

const SECRET = new TextEncoder().encode("s".repeat(32));

describe("session tokens", () => {
  it("round-trips claims", async () => {
    const token = await signSession(SECRET, {
      sub: "user-1",
      email: "a@b.c",
      admin: true,
    });
    const result = await verifySession(SECRET, token);
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.claims.sub, "user-1");
    assert.equal(result.claims.email, "a@b.c");
    assert.equal(result.claims.admin, true);
  });

  it("rejects tampered tokens", async () => {
    const token = await signSession(SECRET, { sub: "u", admin: false });
    const parts = token.split(".");
    parts[1] = parts[1].slice(0, -2) + "xx";
    const result = await verifySession(SECRET, parts.join("."));
    assert.equal(result.ok, false);
  });

  it("rejects tokens signed with a different secret", async () => {
    const token = await signSession(SECRET, { sub: "u", admin: true });
    const other = new TextEncoder().encode("t".repeat(32));
    assert.equal((await verifySession(other, token)).ok, false);
  });

  it("rejects expired tokens", async () => {
    const token = await signSession(SECRET, { sub: "u", admin: true }, -10);
    assert.equal((await verifySession(SECRET, token)).ok, false);
  });

  it("rejects missing or malformed input", async () => {
    assert.equal((await verifySession(SECRET, undefined)).ok, false);
    assert.equal((await verifySession(SECRET, "garbage")).ok, false);
  });

  it("requires a live shared record when a session store is configured", async () => {
    const store = new MemorySessionStore();
    const token = await signSession(SECRET, { sub: "u", admin: true }, 60, store);
    assert.equal((await verifySession(SECRET, token, store)).ok, true);
    await store.reset();
    assert.equal((await verifySession(SECRET, token, store)).ok, false);
  });

  it("does not let shared session data change the signed identity or role", async () => {
    const token = await signSession(SECRET, { sub: "viewer", admin: false });
    const mismatchedStore = {
      put: async () => {},
      get: async () => ({ sub: "attacker", admin: true }),
      delete: async () => {},
      healthCheck: async () => {},
    };

    assert.deepEqual(await verifySession(SECRET, token, mismatchedStore), {
      ok: false,
      reason: "invalid",
    });
  });

  it("distinguishes shared-store outages from invalid or revoked sessions", async () => {
    const store = {
      put: async () => {},
      get: async () => { throw new Error("private backend detail"); },
      delete: async () => {},
      healthCheck: async () => {},
    };
    const token = await signSession(SECRET, { sub: "viewer", admin: false });

    assert.deepEqual(await verifySession(SECRET, token, store), {
      ok: false,
      reason: "store_unavailable",
    });
    assert.deepEqual(await verifySession(SECRET, "malformed-token", store), {
      ok: false,
      reason: "invalid",
    });
  });

  it("surfaces shared-store revocation failures for valid sessions", async () => {
    const token = await signSession(SECRET, { sub: "u", admin: false });
    const failingStore = {
      put: async () => {},
      get: async () => null,
      delete: async () => { throw new Error("session store unavailable"); },
      healthCheck: async () => {},
    };

    await assert.rejects(revokeSession(SECRET, token, failingStore), /session store unavailable/);
  });

  it("keeps logout idempotent for invalid tokens without touching shared storage", async () => {
    let deleteCalls = 0;
    const store = {
      put: async () => {},
      get: async () => null,
      delete: async () => { deleteCalls += 1; },
      healthCheck: async () => {},
    };

    await revokeSession(SECRET, "invalid-token", store);
    assert.equal(deleteCalls, 0);
  });
});

describe("cookies", () => {
  it("parses cookie headers", () => {
    const jar = parseCookieHeader(
      `${SESSION_COOKIE}=abc.def.ghi; theme="dark"; empty=`
    );
    assert.equal(jar[SESSION_COOKIE], "abc.def.ghi");
    assert.equal(jar.theme, "dark");
    assert.equal(jar.empty, "");
  });

  it("returns an empty jar for null headers", () => {
    assert.deepEqual(parseCookieHeader(null), {});
  });

  it("serializes hardened session cookies", () => {
    const c = serializeSetCookie(SESSION_COOKIE, "tok", {
      maxAge: 60,
      secure: true,
    });
    for (const part of [
      `${SESSION_COOKIE}=tok`,
      "Path=/",
      "HttpOnly",
      "SameSite=Lax",
      "Max-Age=60",
      "Secure",
    ]) {
      assert.ok(c.includes(part), `missing ${part}`);
    }
  });

  it("serializes clearing cookies", () => {
    const c = serializeSetCookie("x", "", { maxAge: 0, secure: false });
    assert.ok(c.includes("x=") && c.includes("Max-Age=0"));
    assert.ok(!c.includes("Secure"));
  });
});
