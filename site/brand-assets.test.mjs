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
  assert.match(mark, /viewBox="0 0 64 64"/);
  assert.match(mark, /M32 13 42 17\.5v12\.2/);
  assert.match(mark, /An agent and tool connected across a shield-shaped authorization boundary/);
});

test("light, dark, and monochrome marks preserve one glyph with surface-safe contrast", () => {
  const paths = ["./public/agentguard-mark.svg", "./public/agentguard-mark-dark.svg", "./public/agentguard-mark-mono.svg"]
    .map((path) => read(path));
  const glyph = /<path d="(M32 13 [^"]+)" fill=/;
  assert.deepEqual(paths.map((asset) => asset.match(glyph)?.[1]), [
    paths[0].match(glyph)?.[1],
    paths[0].match(glyph)?.[1],
    paths[0].match(glyph)?.[1],
  ]);
  assert.match(paths[0], /fill="#218263"/);
  assert.match(paths[1], /fill="#0f2f27"/);
  assert.match(paths[2], /stroke="#172420" stroke-width="3"/);
  for (const asset of paths) {
    assert.match(asset, /<title id="title">AgentGuard<\/title>/);
    assert.match(asset, /stroke-linecap="round"/);
  }
});

test("wordmarks and social preview use the selected boundary identity", () => {
  const boundary = /M32 13 42 17\.5v12\.2/;
  for (const path of ["./public/agentguard-wordmark.svg", "./public/agentguard-wordmark-dark.svg", "./public/og-image.svg"]) {
    assert.match(read(path), boundary, `${path} should use the selected glyph`);
  }
  assert.match(read("./public/brand/concept-boundary.svg"), /M160 40 195 55v43/);
  const social = read("./public/og-image.svg");
  assert.match(social, /viewBox="0 0 1200 630"/);
  assert.match(social, /<rect width="280" height="46" rx="23" fill="#79dfbf"\/>/);
  assert.match(social, /<text x="140" y="30" text-anchor="middle"[^>]*>OPEN SOURCE · APACHE-2\.0<\/text>/);
  assert.match(social, /x="96" y="337"[^>]*font-size="64"/);
  assert.match(social, /github\.com\/sachncs\/agent-guard/);
  assert.doesNotMatch(social, /agentguard\.dev/);
  const png = readFileSync(new URL("./public/og-image.png", import.meta.url));
  assert.deepEqual([...png.subarray(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10]);
  assert.equal(png.readUInt32BE(16), 1200);
  assert.equal(png.readUInt32BE(20), 630);
  assert.match(read("./src/layouts/base.astro"), /og-image\.png/);
});
