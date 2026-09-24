import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { MemorySessionStore, RedisSessionStore } from "./session_store.ts";

const claims = { sub: "user-1", admin: true };

describe("session stores", () => {
  it("expires and revokes memory sessions", async () => {
    let now = 0;
    const store = new MemorySessionStore(() => now);
    await store.put("sid", claims, 10);
    assert.deepEqual(await store.get("sid"), claims);
    now = 10_001;
    assert.equal(await store.get("sid"), null);
    await store.put("sid", claims, 60);
    await store.delete("sid");
    assert.equal(await store.get("sid"), null);
  });

  it("bounds memory sessions, prunes expired entries, and preserves live entries at capacity", async () => {
    let now = 0;
    const store = new MemorySessionStore(() => now, 2);
    await store.put("expired", claims, 1);
    await store.put("live", claims, 10);
    await assert.rejects(store.put("overflow", claims, 10), /capacity reached/);
    assert.deepEqual(await store.get("live"), claims, "capacity pressure never evicts a live session");

    now = 1_001;
    await store.put("replacement", claims, 10);
    assert.equal(await store.get("expired"), null, "expired entries are pruned before admitting a new session");
    assert.deepEqual(await store.get("live"), claims);
    assert.deepEqual(await store.get("replacement"), claims);
    await assert.rejects(store.put("invalid-ttl", claims, 0), /ttlSeconds must be a positive safe duration/);
    await assert.rejects(
      store.put("overflow-ttl", claims, Number.MAX_SAFE_INTEGER),
      /ttlSeconds must be a positive safe duration/,
    );
  });

  it("rejects an invalid in-memory session capacity", () => {
    assert.throws(() => new MemorySessionStore(Date.now, 0), /maxSessions must be a positive safe integer/);
  });

  it("uses Redis-compatible SET/GET/DEL commands", async () => {
    const commands: string[][] = [];
    const redirectModes: (RequestRedirect | undefined)[] = [];
    let signal: AbortSignal | undefined;
    const store = new RedisSessionStore(
      "https://redis.example",
      "secret",
      async (_url, init) => {
        signal = init?.signal as AbortSignal;
        redirectModes.push(init?.redirect);
        const command = JSON.parse(String(init?.body)) as string[];
        commands.push(command);
        const result = command[0] === "GET"
          ? JSON.stringify(claims)
          : command[0] === "PING" ? "PONG" : "OK";
        return new Response(JSON.stringify({ result }), { status: 200 });
      },
    );
    await store.put("sid", claims, 600);
    assert.deepEqual(await store.get("sid"), {
      ...claims,
      email: undefined,
      name: undefined,
    });
    await store.delete("sid");
    await store.healthCheck();
    assert.deepEqual(commands.map(([command]) => command), ["SET", "GET", "DEL", "PING"]);
    assert.equal(commands[0][4], "600");
    assert.deepEqual(redirectModes, ["error", "error", "error", "error"]);
    assert.ok(signal, "shared-store requests have a bounded timeout");
  });

  it("namespaces Redis session keys and rejects unsafe prefixes", async () => {
    let command: string[] = [];
    const store = new RedisSessionStore(
      "https://redis.example",
      "secret",
      async (_url, init) => {
        command = JSON.parse(String(init?.body)) as string[];
        return new Response(JSON.stringify({ result: "OK" }), { status: 200 });
      },
      "staging:console:session:",
    );
    await store.put("sid", claims, 60);
    assert.equal(command[1], "staging:console:session:sid");
    assert.throws(
      () => new RedisSessionStore("https://redis.example", "secret", fetch, "bad prefix/"),
      /session Redis key prefix/,
    );
  });

  it("bounds a stalled Redis request", async () => {
    const store = new RedisSessionStore(
      "https://redis.example",
      "secret",
      async (_url, init) =>
        new Promise<Response>((_, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("timed out")));
        }),
      "agentguard:test:",
      1,
    );
    await assert.rejects(store.get("sid"), (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.match(error.message, /Redis-compatible store request failed/);
      assert.match(String(error.cause), /timed out|aborted/i);
      return true;
    });
  });
});
