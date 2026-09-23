import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");

test("site chrome uses the shipped boundary mark instead of a hand-drawn copy", () => {
  const component = read("./src/components/logo.astro");
  assert.match(component, /agentguard-mark\.svg/);
  assert.match(component, /agentguard-mark-mono\.svg/);
  assert.match(component, /import\.meta\.env\.BASE_URL/);
  assert.match(component, /aria-hidden="true"/);
  assert.doesNotMatch(component, /<svg\b/);
});

test("favicon, site mark, and console mark remain the same selected glyph", () => {
  const mark = read("./public/agentguard-mark.svg");
  assert.equal(read("./public/favicon.svg"), mark);
  assert.equal(read("../frontend/public/agentguard-mark.svg"), mark);
  assert.match(mark, /M32 14v36/);
});
