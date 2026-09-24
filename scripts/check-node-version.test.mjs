import assert from "node:assert/strict";
import test from "node:test";
import { isSupportedNodeVersion } from "./check-node-version.mjs";

test("accepts the minimum supported Node.js release and newer majors", () => {
  for (const version of ["22.12.0", "22.19.0", "v26.8.1"]) {
    assert.equal(isSupportedNodeVersion(version), true, version);
  }
});

test("rejects older, malformed, and incomplete Node.js versions", () => {
  for (const version of ["18.20.0", "20.9.0", "22.11.9", "22.12", "not-a-version", ""]) {
    assert.equal(isSupportedNodeVersion(version), false, version);
  }
});
