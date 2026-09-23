import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { checkPdpReady } from "./pdp_health.ts";

describe("PDP readiness probe", () => {
  it("checks the readiness endpoint with credentials and a bounded deadline", async () => {
    let target = "";
    let request: RequestInit | undefined;
    await checkPdpReady("http://pdp:8443", "internal-token", async (input, init) => {
      target = String(input);
      request = init;
      return new Response("ready", { status: 200 });
    });
    assert.equal(target, "http://pdp:8443/readyz");
    assert.equal(new Headers(request?.headers).get("authorization"), "Bearer internal-token");
    assert.ok(request?.signal, "probe must have a timeout");
    assert.equal(request?.cache, "no-store");
  });

  it("rejects non-ready PDP responses", async () => {
    await assert.rejects(
      checkPdpReady("http://pdp:8443", undefined, async () =>
        new Response("unavailable", { status: 503 })),
      /HTTP 503/,
    );
  });

  it("normalizes unreachable PDP errors", async () => {
    await assert.rejects(
      checkPdpReady("http://pdp:8443", undefined, async () => {
        throw new Error("connection refused");
      }),
      /PDP readiness probe failed/,
    );
  });
});
