import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { LatestRequest } from "./latest_request.ts";

describe("LatestRequest", () => {
  it("aborts superseded work and marks only the newest result current", () => {
    const requests = new LatestRequest();
    const old = requests.begin();
    const current = requests.begin();

    assert.equal(old.signal.aborted, true);
    assert.equal(old.isCurrent(), false);
    assert.equal(current.signal.aborted, false);
    assert.equal(current.isCurrent(), true);
    assert.equal(requests.active, true);
  });

  it("clears only the active request and invalidates work on teardown", () => {
    const requests = new LatestRequest();
    const old = requests.begin();
    const current = requests.begin();
    old.finish();
    assert.equal(requests.active, true, "stale cleanup cannot clear the active request");

    current.finish();
    assert.equal(requests.active, false);
    const pending = requests.begin();
    requests.abort();
    assert.equal(pending.signal.aborted, true);
    assert.equal(pending.isCurrent(), false);
    assert.equal(requests.active, false);
  });
});
