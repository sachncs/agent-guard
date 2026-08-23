import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { resetAuthConfigCache, authConfig } from "./config.ts";

const BASE_ENV: Record<string, string> = {
  AGENTGUARD_OIDC_ISSUER: "https://idp.example.com",
  AGENTGUARD_OIDC_CLIENT_ID: "agentguard-console",
  AGENTGUARD_OIDC_CLIENT_SECRET: "client-secret",
  AGENTGUARD_SESSION_SECRET: "s".repeat(32),
};

describe("auth config", () => {
  beforeEach(() => {
    resetAuthConfigCache();
    for (const key of Object.keys(process.env)) {
      if (key.startsWith("AGENTGUARD_")) delete process.env[key];
    }
  });

  it("is invalid when required variables are missing", () => {
    const cfg = authConfig();
    assert.ok(!cfg.valid, "config must be invalid");
    if (cfg.valid) return;
    assert.match(cfg.reason, /AGENTGUARD_SESSION_SECRET/);
  });

  it("names every missing variable", () => {
    process.env.AGENTGUARD_SESSION_SECRET = "x".repeat(32);
    const cfg = authConfig();
    assert.ok(!cfg.valid, "config must be invalid");
    if (cfg.valid) return;
    assert.match(cfg.reason, /AGENTGUARD_OIDC_ISSUER/);
  });

  it("rejects short session secrets", () => {
    for (const [k, v] of Object.entries(BASE_ENV)) process.env[k] = v;
    process.env.AGENTGUARD_SESSION_SECRET = "short";
    const cfg = authConfig();
    assert.ok(!cfg.valid, "config must be invalid");
    if (cfg.valid) return;
    assert.match(cfg.reason, /at least 32/);
  });

  it("parses a complete configuration", () => {
    for (const [k, v] of Object.entries(BASE_ENV)) process.env[k] = v;
    process.env.AGENTGUARD_ADMIN_CLAIM = "roles";
    process.env.AGENTGUARD_ADMIN_VALUES = "a, b ,";
    process.env.AGENTGUARD_PDP_URL = "http://pdp:8443/";

    const cfg = authConfig();
    assert.equal(cfg.valid, true);
    if (!cfg.valid) return;
    assert.equal(cfg.config.oidc.issuer, "https://idp.example.com");
    assert.equal(cfg.config.adminClaim, "roles");
    assert.deepEqual(cfg.config.adminValues, ["a", "b"]);
    assert.equal(cfg.config.pdpUrl, "http://pdp:8443");
    assert.equal(cfg.config.insecureCookie, false);
  });
});
