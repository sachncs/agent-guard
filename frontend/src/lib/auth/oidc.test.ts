import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import type { AuthConfig } from "./config.ts";
import { discover, OidcError, resetDiscoveryCache } from "./oidc.ts";

const config: AuthConfig = {
  oidc: {
    issuer: "https://idp.example",
    clientId: "console",
    clientSecret: "not-used",
  },
  sessionSecret: new Uint8Array(32),
  adminClaim: "groups",
  adminValues: [],
  pdpUrl: "http://127.0.0.1:8443",
  trustProxyHeaders: true,
  insecureCookie: false,
};

const originalFetch = globalThis.fetch;
const env = process.env as Record<string, string | undefined>;
const originalNodeEnv = env.NODE_ENV;

afterEach(() => {
  globalThis.fetch = originalFetch;
  if (originalNodeEnv === undefined) delete env.NODE_ENV;
  else env.NODE_ENV = originalNodeEnv;
  resetDiscoveryCache();
});

describe("OIDC discovery", () => {
  it("rejects plaintext metadata endpoints in production", async () => {
    env.NODE_ENV = "production";
    globalThis.fetch = async (_url, options) => {
      assert.equal(options?.redirect, "error", "discovery must not follow TLS downgrade redirects");
      return Response.json({
        authorization_endpoint: "https://idp.example/authorize",
        token_endpoint: "http://idp.example/token",
        jwks_uri: "https://idp.example/jwks",
      });
    };

    await assert.rejects(discover(config), {
      name: OidcError.name,
      message: /HTTPS in production/,
    });
  });
});
