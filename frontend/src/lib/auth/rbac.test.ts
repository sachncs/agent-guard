import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { resolveRole } from "./rbac.ts";

const cfg = { adminClaim: "groups", adminValues: ["agentguard-admins"] };

describe("role resolution", () => {
  it("grants admin on matching group", () => {
    assert.equal(
      resolveRole(cfg, { groups: ["users", "agentguard-admins"] }),
      "admin"
    );
  });

  it("stays viewer without a match", () => {
    assert.equal(resolveRole(cfg, { groups: ["users"] }), "viewer");
  });

  it("handles string-valued claims", () => {
    assert.equal(resolveRole(cfg, { groups: "agentguard-admins" }), "admin");
    assert.equal(resolveRole(cfg, { groups: "nobody" }), "viewer");
  });

  it("honors a custom claim name", () => {
    assert.equal(
      resolveRole(
        { adminClaim: "roles", adminValues: ["ops"] },
        { roles: ["ops"] }
      ),
      "admin"
    );
  });

  it("never grants admin when no values are configured", () => {
    const empty = { adminClaim: "groups", adminValues: [] };
    assert.equal(resolveRole(empty, { groups: ["agentguard-admins"] }), "viewer");
    assert.equal(resolveRole(empty, {}), "viewer");
  });
});
