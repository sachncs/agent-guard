import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { decisionPresentation } from "./decision_presentation.ts";

describe("decision presentation", () => {
  it("uses the positive semantic token for allow", () => {
    assert.deepEqual(decisionPresentation("allow"), {
      label: "ALLOW",
      ariaLabel: "Authorization allowed",
      className: "border-allow text-allow",
    });
  });

  it("uses the destructive semantic token for deny", () => {
    assert.deepEqual(decisionPresentation("deny"), {
      label: "DENY",
      ariaLabel: "Authorization denied",
      className: "border-deny text-deny",
    });
  });
});
