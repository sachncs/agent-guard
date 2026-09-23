import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseJsonObject } from "./json_object.ts";

describe("parseJsonObject", () => {
  it("parses nested JSON objects", () => {
    assert.deepEqual(parseJsonObject('{"args":{"to":"bob"}}', "Arguments"), {
      ok: true,
      value: { args: { to: "bob" } },
    });
  });

  it("treats an empty optional context as an empty object", () => {
    assert.deepEqual(parseJsonObject("  \n ", "Arguments"), { ok: true, value: {} });
  });

  it("rejects malformed JSON with a field-specific message", () => {
    assert.deepEqual(parseJsonObject("{bad", "Arguments"), {
      ok: false,
      error: "Arguments must contain valid JSON.",
    });
  });

  it("rejects arrays and scalar JSON values", () => {
    for (const value of ["[]", "null", "\"text\"", "7", "true"]) {
      assert.deepEqual(parseJsonObject(value, "Session"), {
        ok: false,
        error: "Session must be a JSON object.",
      });
    }
  });
});
