import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { BoundedJsonResponseError, readBoundedJson } from "./bounded_json.ts";

describe("readBoundedJson", () => {
  it("cancels a body that does not finish before its deadline", async () => {
    let canceled = false;
    const body = new ReadableStream<Uint8Array<ArrayBuffer>>({
      cancel() {
        canceled = true;
      },
    });
    await assert.rejects(
      readBoundedJson(
        { headers: new Headers(), body },
        1024,
        "test upstream",
        10,
      ),
      (error: unknown) =>
        error instanceof BoundedJsonResponseError &&
        error.message === "test upstream response body timed out",
    );
    assert.equal(canceled, true);
  });

  it("parses a body exactly at its byte limit", async () => {
    assert.deepEqual(
      await readBoundedJson(Response.json({ ok: true }), 11, "test"),
      { ok: true },
    );
  });
});
