import test from "node:test";
import assert from "node:assert/strict";
import { validateRenderedImages } from "./validate-production-overlay.mjs";

const pdp = `registry.example.org/team/agentguard-server@sha256:${"a".repeat(64)}`;
const consoleImage = `registry.example.org/team/agentguard-console@sha256:${"b".repeat(64)}`;
const render = (images) => images.map((image) => `image: ${image}`).join("\n");

test("accepts one immutable registry digest for each production workload", () => {
  assert.deepEqual(validateRenderedImages(render([pdp, consoleImage])), []);
});

test("rejects sample tags and placeholder digests", () => {
  const failures = validateRenderedImages(render([
    "agentguard-server:0.2.0",
    `registry.example.com/security/agentguard-console@sha256:${"b".repeat(64)}`,
  ]));
  assert.equal(failures.length, 2);
  assert.match(failures.join(" "), /agentguard-server.*fully qualified/);
  assert.match(failures.join(" "), /agentguard-console.*64-hex sha256 digest/);
});

test("rejects missing, duplicate, and malformed production image references", () => {
  assert.match(
    validateRenderedImages(render([pdp])).join(" "),
    /expected exactly one agentguard-console image, found 0/,
  );
  assert.match(
    validateRenderedImages(render([pdp, pdp, consoleImage])).join(" "),
    /expected exactly one agentguard-server image, found 2/,
  );
  assert.match(
    validateRenderedImages(render([
      "registry.example.org/team/agentguard-server@sha256:xyz",
      consoleImage,
    ])).join(" "),
    /agentguard-server must use a fully qualified/,
  );
});
