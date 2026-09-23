import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { MAX_REDIS_RESPONSE_BYTES, RedisRestClient } from "./redis_rest.ts";

describe("Redis REST transport", () => {
  it("sends authenticated commands without redirects or caching", async () => {
    let target = "";
    let request: RequestInit | undefined;
    const client = new RedisRestClient("https://redis.example", "token", async (input, init) => {
      target = String(input);
      request = init;
      return Response.json({ result: "PONG" });
    });

    assert.equal(await client.command(["PING"]), "PONG");
    assert.equal(target, "https://redis.example");
    assert.equal(request?.method, "POST");
    assert.equal(new Headers(request?.headers).get("authorization"), "Bearer token");
    assert.equal(request?.redirect, "error");
    assert.equal(request?.cache, "no-store");
    assert.ok(request?.signal);
    assert.deepEqual(JSON.parse(String(request?.body)), ["PING"]);
  });

  it("validates HTTP status and the Redis REST response envelope", async () => {
    const responses = [
      new Response("backend detail", { status: 503 }),
      new Response("not-json", { status: 200 }),
      Response.json(["PONG"]),
      Response.json({ error: "secret backend detail" }),
      Response.json({ other: "value" }),
    ];
    for (const response of responses) {
      const client = new RedisRestClient("https://redis.example", "token", async () => response);
      await assert.rejects(client.command(["PING"]), /Redis-compatible store/);
    }
  });

  it("cancels oversized responses declared by Content-Length", async () => {
    let cancelled = false;
    const response = new Response(new ReadableStream({
      cancel() { cancelled = true; },
    }), {
      status: 200,
      headers: { "content-length": String(MAX_REDIS_RESPONSE_BYTES + 1) },
    });
    const client = new RedisRestClient("https://redis.example", "token", async () => response);
    await assert.rejects(client.command(["PING"]), /size limit/);
    assert.equal(cancelled, true);
  });

  it("enforces the limit on streamed bodies when length is absent or false", async () => {
    const bytes = new TextEncoder().encode(" ".repeat(MAX_REDIS_RESPONSE_BYTES + 1));
    const response = new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(bytes.subarray(0, 128 * 1024));
        controller.enqueue(bytes.subarray(128 * 1024));
        controller.close();
      },
    }), { status: 200, headers: { "content-length": "1" } });
    const client = new RedisRestClient("https://redis.example", "token", async () => response);
    await assert.rejects(client.command(["PING"]), /size limit/);
  });

  it("accepts a valid response exactly at the byte limit", async () => {
    const prefix = '{"result":"';
    const suffix = '"}';
    const value = "x".repeat(
      MAX_REDIS_RESPONSE_BYTES - Buffer.byteLength(prefix) - Buffer.byteLength(suffix),
    );
    const client = new RedisRestClient("https://redis.example", "token", async () =>
      new Response(`${prefix}${value}${suffix}`, { status: 200 }));
    assert.equal(await client.command(["GET", "session"]), value);
  });

  it("uses the shared command contract for health checks", async () => {
    let command: unknown;
    const client = new RedisRestClient("https://redis.example", "token", async (_input, init) => {
      command = JSON.parse(String(init?.body));
      return Response.json({ result: "PONG" });
    });
    await client.healthCheck();
    assert.deepEqual(command, ["PING"]);
  });
});
