import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { checkPdpReady } from "./pdp_health.ts";

describe("PDP readiness probe", () => {
  it("checks the readiness endpoint with credentials and a bounded deadline", async () => {
    let target = "";
    let request: RequestInit | undefined;
    let bodyCancelled = false;
    await checkPdpReady("http://pdp:8443", "internal-token", async (input, init) => {
      target = String(input);
      request = init;
      return new Response(new ReadableStream({
        cancel() { bodyCancelled = true; },
      }), { status: 200 });
    });
    assert.equal(target, "http://pdp:8443/readyz");
    assert.equal(new Headers(request?.headers).get("authorization"), "Bearer internal-token");
    assert.ok(request?.signal, "probe must have a timeout");
    assert.equal(request?.cache, "no-store");
    assert.equal(request?.redirect, "error", "credential-bearing probes must reject redirects");
    assert.equal(bodyCancelled, true, "unused readiness response body is released");
  });

  it("rejects non-ready PDP responses", async () => {
    let bodyCancelled = false;
    await assert.rejects(
      checkPdpReady("http://pdp:8443", undefined, async () =>
        new Response(new ReadableStream({
          cancel() { bodyCancelled = true; },
        }), { status: 503 })),
      /HTTP 503/,
    );
    assert.equal(bodyCancelled, true, "error response bodies are released too");
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
