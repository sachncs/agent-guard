import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  SESSION_COOKIE,
  parseCookieHeader,
  serializeSetCookie,
  signSession,
  verifySession,
} from "./session.ts";

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
