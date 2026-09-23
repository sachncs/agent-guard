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
    assert.equal(cfg.config.trustProxyHeaders, false);
  });

  it("requires an HTTPS OIDC issuer in production", () => {
    for (const [k, v] of Object.entries(BASE_ENV)) process.env[k] = v;
    const env = process.env as Record<string, string | undefined>;
    const previousNodeEnv = env.NODE_ENV;
    env.NODE_ENV = "production";
    env.AGENTGUARD_OIDC_ISSUER = "http://idp.example";
    try {
      const cfg = authConfig();
      assert.equal(cfg.valid, false);
      if (!cfg.valid) assert.match(cfg.reason, /OIDC_ISSUER.*HTTPS/);
    } finally {
      if (previousNodeEnv === undefined) delete env.NODE_ENV;
      else env.NODE_ENV = previousNodeEnv;
      resetAuthConfigCache();
    }
  });

  it("requires Redis sessions for production mode", () => {
    for (const [k, v] of Object.entries(BASE_ENV)) process.env[k] = v;
    (process.env as Record<string, string | undefined>).NODE_ENV = "production";
    let cfg = authConfig();
    assert.equal(cfg.valid, false);
    if (cfg.valid) return;
    assert.match(cfg.reason, /SESSION_REDIS/);

    process.env.AGENTGUARD_SESSION_REDIS_URL = "https://redis.example";
    process.env.AGENTGUARD_SESSION_REDIS_TOKEN = "secret";
    process.env.AGENTGUARD_TRUST_PROXY_HEADERS = "1";
    process.env.AGENTGUARD_PDP_BEARER = "pdp-secret";
    resetAuthConfigCache();
    cfg = authConfig();
    assert.equal(cfg.valid, true);
    delete (process.env as Record<string, string | undefined>).NODE_ENV;
  });

  it("rejects non-HTTPS and credential-bearing production session URLs", () => {
    for (const [k, v] of Object.entries(BASE_ENV)) process.env[k] = v;
    const env = process.env as Record<string, string | undefined>;
    const previousNodeEnv = env.NODE_ENV;
    env.NODE_ENV = "production";
    env.AGENTGUARD_SESSION_REDIS_TOKEN = "secret";
    env.AGENTGUARD_TRUST_PROXY_HEADERS = "1";
    try {
      env.AGENTGUARD_SESSION_REDIS_URL = "http://redis.example";
      assert.equal(authConfig().valid, false);
      resetAuthConfigCache();
      env.AGENTGUARD_SESSION_REDIS_URL = "https://user:pass@redis.example";
      const cfg = authConfig();
      assert.equal(cfg.valid, false);
      if (!cfg.valid) assert.match(cfg.reason, /URL credentials/);
    } finally {
      if (previousNodeEnv === undefined) delete env.NODE_ENV;
      else env.NODE_ENV = previousNodeEnv;
      resetAuthConfigCache();
    }
  });

  it("requires explicitly trusted proxy headers in production", () => {
    for (const [k, v] of Object.entries(BASE_ENV)) process.env[k] = v;
    const env = process.env as Record<string, string | undefined>;
    const previousNodeEnv = env.NODE_ENV;
    env.NODE_ENV = "production";
    env.AGENTGUARD_SESSION_STORE = "redis";
    env.AGENTGUARD_SESSION_REDIS_URL = "https://redis.example";
    env.AGENTGUARD_SESSION_REDIS_TOKEN = "secret";

    try {
      let cfg = authConfig();
      assert.equal(cfg.valid, false);
      if (!cfg.valid) assert.match(cfg.reason, /TRUST_PROXY_HEADERS=1/);

      env.AGENTGUARD_TRUST_PROXY_HEADERS = "true";
      resetAuthConfigCache();
      cfg = authConfig();
      assert.equal(cfg.valid, false);
      if (!cfg.valid) assert.match(cfg.reason, /must be 0 or 1/);

      env.AGENTGUARD_TRUST_PROXY_HEADERS = "1";
      resetAuthConfigCache();
      cfg = authConfig();
      assert.equal(cfg.valid, false, "production requires authenticated PDP access");
      if (!cfg.valid) assert.match(cfg.reason, /PDP_BEARER/);

      env.AGENTGUARD_PDP_BEARER = "pdp-secret";
      resetAuthConfigCache();
      cfg = authConfig();
      assert.equal(cfg.valid, true);
      if (cfg.valid) assert.equal(cfg.config.trustProxyHeaders, true);
    } finally {
      if (previousNodeEnv === undefined) delete env.NODE_ENV;
      else env.NODE_ENV = previousNodeEnv;
      resetAuthConfigCache();
    }
  });

  it("rejects an explicit memory session store in production", () => {
    for (const [k, v] of Object.entries(BASE_ENV)) process.env[k] = v;
    const env = process.env as Record<string, string | undefined>;
    const previousNodeEnv = env.NODE_ENV;
    const previousStore = env.AGENTGUARD_SESSION_STORE;
    env.NODE_ENV = "production";
    env.AGENTGUARD_SESSION_STORE = "memory";

    try {
      const cfg = authConfig();
      assert.equal(cfg.valid, false);
      if (!cfg.valid) assert.match(cfg.reason, /SESSION_STORE=redis/);
    } finally {
      if (previousNodeEnv === undefined) delete env.NODE_ENV;
      else env.NODE_ENV = previousNodeEnv;
      if (previousStore === undefined) delete env.AGENTGUARD_SESSION_STORE;
      else env.AGENTGUARD_SESSION_STORE = previousStore;
      resetAuthConfigCache();
    }
  });
});
