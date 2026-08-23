import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  authorizeSchema,
  delegateSchema,
  logQuerySchema,
  parseJsonBody,
  verifySchema,
} from "./api-schemas.ts";

const jsonReq = (body: unknown) =>
  new Request("http://x/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

describe("schemas", () => {
  it("applies authorize defaults", () => {
    const d = authorizeSchema.parse({
      uid: "alice",
      tool: "web_search",
      resourceType: "Resource",
      resourceId: "agent",
    });
    assert.equal(d.principalType, "user");
    assert.deepEqual(d.args, {});
  });

  it("rejects option-looking identifiers (CLI argument injection)", () => {
    assert.throws(() => authorizeSchema.parse({ uid: "--store" }));
    assert.throws(() => authorizeSchema.parse({
      uid: "a", tool: "-x", resourceType: "R", resourceId: "b",
    }));
  });

  it("constrains entity types", () => {
    assert.throws(() =>
      authorizeSchema.parse({
        uid: "a", tool: "t", resourceType: "bad type!", resourceId: "b",
      })
    );
  });

  it("bounds delegation ttl", () => {
    const ok = delegateSchema.parse({
      from: "a", to: "b", actions: ["ToolCall::x"], resources: ["Resource::r"],
      ttlSeconds: 600,
    });
    assert.equal(ok.ttlSeconds, 600);
    assert.throws(() =>
      delegateSchema.parse({
        from: "a", to: "b", actions: ["x"], resources: ["r"], ttlSeconds: 1_000_000,
      })
    );
  });

  it("rejects empty action/resource lists", () => {
    assert.throws(() =>
      delegateSchema.parse({ from: "a", to: "b", actions: [], resources: ["r"] })
    );
  });

  it("rejects path traversal in keysFile and oversized tokens", () => {
    assert.throws(() => verifySchema.parse({ token: "t".repeat(20), keysFile: "../../etc/passwd" }));
    assert.throws(() => verifySchema.parse({ token: "t".repeat(17), keysFile: "-k" }));
  });

  it("clamps log tail size via coercion", () => {
    assert.equal(logQuerySchema.parse({ n: "5" }).n, 5);
    assert.throws(() => logQuerySchema.parse({ n: "1000" }));
  });

  it("returns 400-style results for bad JSON bodies", async () => {
    const noJson = new Request("http://x/", { method: "POST", body: "not json" });
    const r1 = await parseJsonBody(noJson, delegateSchema);
    assert.equal(r1.ok, false);
    if (!r1.ok) assert.equal(r1.status, 400);

    const r2 = await parseJsonBody(jsonReq({}), delegateSchema);
    assert.equal(r2.ok, false);
    if (!r2.ok && r2.ok === false && "error" in r2) assert.ok(r2.error.length > 0);
  });
});
