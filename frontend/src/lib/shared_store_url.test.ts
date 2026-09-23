import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { validateSharedStoreUrl } from "./shared_store_url.ts";

describe("shared-store endpoint URLs", () => {
  it("requires HTTPS in production", () => {
    assert.match(validateSharedStoreUrl("http://redis.example", true) ?? "", /HTTPS/);
    assert.equal(validateSharedStoreUrl("https://redis.example", true), undefined);
  });
  it("allows HTTP only outside production", () => {
    assert.equal(validateSharedStoreUrl("http://127.0.0.1:8079", false), undefined);
    assert.match(validateSharedStoreUrl("ftp://redis.example", false) ?? "", /HTTP or HTTPS/);
  });
  it("rejects embedded credentials and malformed URLs", () => {
    assert.match(validateSharedStoreUrl("https://user:pass@redis.example", true) ?? "", /URL credentials/);
    assert.match(validateSharedStoreUrl("not a URL", true) ?? "", /absolute URL/);
  });
});
