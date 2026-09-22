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

  it("uses Redis-compatible SET/GET/DEL commands", async () => {
    const commands: string[][] = [];
    const store = new RedisSessionStore(
      "https://redis.example",
      "secret",
      async (_url, init) => {
        const command = JSON.parse(String(init?.body)) as string[];
        commands.push(command);
        const result = command[0] === "GET" ? JSON.stringify(claims) : "OK";
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
    assert.deepEqual(commands.map(([command]) => command), ["SET", "GET", "DEL"]);
    assert.equal(commands[0][4], "600");
  });
});
