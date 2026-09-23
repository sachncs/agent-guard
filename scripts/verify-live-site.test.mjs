import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { extractLocations, isWithinSite } from "./verify-live-site.mjs";

describe("live site smoke helpers", () => {
  it("extracts and decodes sitemap locations", () => {
    assert.deepEqual(
      extractLocations("<urlset><url><loc>https://docs.example/agent-guard/a&amp;b/</loc></url></urlset>"),
      ["https://docs.example/agent-guard/a&b/"],
    );
  });

  it("accepts same-origin routes within a project Pages base path", () => {
    assert.equal(isWithinSite("https://docs.example/agent-guard/docs/", "https://docs.example/agent-guard/"), true);
    assert.equal(isWithinSite("https://docs.example/agent-guard", "https://docs.example/agent-guard/"), true);
  });

  it("rejects off-origin and path-prefix-confusion URLs", () => {
    const site = "https://docs.example/agent-guard/";
    assert.equal(isWithinSite("https://attacker.example/agent-guard/docs/", site), false);
    assert.equal(isWithinSite("https://docs.example/agent-guard-evil/docs/", site), false);
    assert.equal(isWithinSite("https://docs.example/other/", site), false);
  });
});
