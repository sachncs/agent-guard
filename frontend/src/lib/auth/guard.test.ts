import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { requireAdmin, requireViewer } from "./guard.ts";
import { SESSION_COOKIE, signSession } from "./session.ts";

const SECRET = new TextEncoder().encode("s".repeat(32));

describe("route authentication guards", () => {
  it("returns a sanitized 503 for store outages, not an authentication 401", async () => {
    const token = await signSession(SECRET, { sub: "admin", admin: true });
    const request = new Request("https://console.example/api/log", {
      headers: { cookie: `${SESSION_COOKIE}=${token}` },
    });
    const unavailableStore = {
      put: async () => {},
      get: async () => { throw new Error("backend hostname and credentials"); },
      delete: async () => {},
      healthCheck: async () => {},
    };

    for (const guard of [requireViewer, requireAdmin]) {
      const result = await guard(SECRET, request, unavailableStore);
      assert.ok(result instanceof Response);
      assert.equal(result.status, 503);
      assert.equal(result.headers.get("cache-control"), "no-store");
      assert.deepEqual(await result.json(), {
        error: "session verification is temporarily unavailable",
        kind: "session_store_unavailable",
      });
    }

    const invalidSession = await requireViewer(
      SECRET,
      new Request("https://console.example/api/log"),
      unavailableStore,
    );
    assert.ok(invalidSession instanceof Response);
    assert.equal(invalidSession.status, 401);
  });
});
