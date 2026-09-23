import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { evaluate, PdpUnavailable } from "./pdp.ts";

const request = {
  subject: { type: "Agent", id: "research" },
  action: { type: "Action", id: "ToolCall::repo_read" },
  resource: { type: "Repository", id: "demo" },
};

describe("PDP evaluation client", () => {
  it("sends a bounded, non-redirecting authenticated request and parses a decision", async () => {
    let target = "";
    let init: RequestInit | undefined;
    const result = await evaluate("https://pdp.example", "service-token", request, async (input, options) => {
      target = String(input);
      init = options;
      return Response.json({ decision: true, reason: "matched" });
    });

    assert.equal(target, "https://pdp.example/access/v1/evaluation");
    assert.equal(init?.method, "POST");
    assert.equal(new Headers(init?.headers).get("authorization"), "Bearer service-token");
    assert.equal(init?.cache, "no-store");
    assert.equal(init?.redirect, "error");
    assert.ok(init?.signal);
    assert.deepEqual(JSON.parse(String(init?.body)), request);
    assert.deepEqual(result, { decision: true, reason: "matched" });
  });

  it("normalizes unreachable PDP failures", async () => {
    await assert.rejects(
      evaluate("https://pdp.example", undefined, request, async () => {
        throw new Error("private network detail");
      }),
      (error: unknown) => error instanceof PdpUnavailable && /PDP unreachable/.test(error.message),
    );
  });

  it("rejects HTTP failures without parsing their bodies", async () => {
    await assert.rejects(
      evaluate("https://pdp.example", undefined, request, async () =>
        new Response("internal diagnostic", { status: 503 })),
      (error: unknown) => error instanceof PdpUnavailable && /HTTP 503/.test(error.message),
    );
  });

  it("normalizes malformed JSON and invalid decision shapes", async () => {
    for (const response of [
      new Response("not-json", { status: 200 }),
      Response.json({ decision: "allow" }),
      new Response(null, { status: 200 }),
    ]) {
      await assert.rejects(
        evaluate("https://pdp.example", undefined, request, async () => response),
        PdpUnavailable,
      );
    }
  });

  it("rejects oversized declared bodies before reading them", async () => {
    let cancelled = false;
    const response = new Response(new ReadableStream({
      cancel() { cancelled = true; },
    }), {
      status: 200,
      headers: { "content-length": String(256 * 1024 + 1) },
    });
    await assert.rejects(
      evaluate("https://pdp.example", undefined, request, async () => response),
      (error: unknown) => error instanceof PdpUnavailable && /size limit/.test(error.message),
    );
    assert.equal(cancelled, true);
  });

  it("enforces the response limit when content length is missing or understated", async () => {
    const bytes = new TextEncoder().encode(" ".repeat(256 * 1024 + 1));
    const response = new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(bytes.subarray(0, 128 * 1024));
        controller.enqueue(bytes.subarray(128 * 1024));
        controller.close();
      },
    }), { status: 200, headers: { "content-length": "1" } });
    await assert.rejects(
      evaluate("https://pdp.example", undefined, request, async () => response),
      (error: unknown) => error instanceof PdpUnavailable && /size limit/.test(error.message),
    );
  });

  it("accepts a response exactly at the byte limit", async () => {
    const prefix = '{"decision":true,"reason":"';
    const suffix = '"}';
    const reason = "a".repeat(256 * 1024 - Buffer.byteLength(prefix) - Buffer.byteLength(suffix));
    const result = await evaluate(
      "https://pdp.example",
      undefined,
      request,
      async () => new Response(`${prefix}${reason}${suffix}`, { status: 200 }),
    );
    assert.equal(result.decision, true);
    assert.equal(result.reason?.length, reason.length);
  });

  it("rejects invalid UTF-8 instead of treating it as a decision", async () => {
    const response = new Response(new Uint8Array([0xff, 0xfe]), { status: 200 });
    await assert.rejects(
      evaluate("https://pdp.example", undefined, request, async () => response),
      (error: unknown) => error instanceof PdpUnavailable && /UTF-8/.test(error.message),
    );
  });
});
