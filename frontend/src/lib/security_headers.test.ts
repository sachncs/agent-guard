import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { securityHeaders } from "./security_headers.ts";

describe("security headers", () => {
  it("sets the core hardening set", () => {
    const h = securityHeaders(true, true);
    assert.match(h["Content-Security-Policy"], /frame-ancestors 'none'/);
    assert.match(h["Content-Security-Policy"], /object-src 'none'/);
    assert.equal(h["X-Frame-Options"], "DENY");
    assert.equal(h["X-Content-Type-Options"], "nosniff");
    assert.match(h["Referrer-Policy"], /strict-origin/);
  });

  it("allows unsafe-eval only outside production (Next dev needs it)", () => {
    assert.ok(!securityHeaders(true, true)["Content-Security-Policy"].includes("unsafe-eval"));
    assert.ok(securityHeaders(false, false)["Content-Security-Policy"].includes("unsafe-eval"));
  });

  it("sends HSTS only over https", () => {
    assert.ok(securityHeaders(true, true)["Strict-Transport-Security"]);
    assert.ok(!securityHeaders(true, false)["Strict-Transport-Security"]);
  });
});
