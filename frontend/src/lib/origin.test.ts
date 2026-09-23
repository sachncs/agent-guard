import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { isSameOriginRequest } from "./origin.ts";

describe("same-origin request guard", () => {
  it("accepts an exact matching Origin", () => {
    const request = new Request("https://console.example/api/auth/logout", {
      method: "POST",
      headers: { origin: "https://console.example" },
    });
    assert.equal(isSameOriginRequest(request), true);
  });

  it("rejects cross-origin, malformed, and missing browser signals", () => {
    const crossOrigin = new Request("https://console.example/api/auth/logout", {
      method: "POST",
      headers: { origin: "https://attacker.example" },
    });
    assert.equal(isSameOriginRequest(crossOrigin), false);

    const malformed = new Request("https://console.example/api/auth/logout", {
      method: "POST",
      headers: { origin: "null" },
    });
    assert.equal(isSameOriginRequest(malformed), false);

    const missing = new Request("https://console.example/api/auth/logout", { method: "POST" });
    assert.equal(isSameOriginRequest(missing), false);
  });

  it("uses Fetch Metadata only when Origin is absent", () => {
    const sameOrigin = new Request("https://console.example/api/auth/logout", {
      method: "POST",
      headers: { "sec-fetch-site": "same-origin" },
    });
    const sameSite = new Request("https://console.example/api/auth/logout", {
      method: "POST",
      headers: { "sec-fetch-site": "same-site" },
    });
    assert.equal(isSameOriginRequest(sameOrigin), true);
    assert.equal(isSameOriginRequest(sameSite), false);
  });

  it("uses only singular trusted forwarded host/protocol behind a proxy", () => {
    const proxied = new Request("http://localhost:3000/api/auth/logout", {
      method: "POST",
      headers: {
        origin: "https://console.example",
        "x-forwarded-host": "console.example",
        "x-forwarded-proto": "https",
      },
    });
    assert.equal(isSameOriginRequest(proxied, true), true);

    const forwardedChain = new Request("http://localhost:3000/api/auth/logout", {
      method: "POST",
      headers: {
        origin: "https://console.example",
        "x-forwarded-host": "console.example, attacker.example",
        "x-forwarded-proto": "https",
      },
    });
    assert.equal(isSameOriginRequest(forwardedChain, true), false);
  });
});
