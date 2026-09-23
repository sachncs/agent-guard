import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { exportJWK, generateKeyPair, SignJWT, jwtVerify } from "jose";
import type { AuthConfig } from "./config.ts";
import {
  buildLoginRedirect,
  completeLogin,
  discover,
  OidcError,
  resetDiscoveryCache,
} from "./oidc.ts";

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

  it("isolates cached endpoints by issuer and reuses each issuer's discovery", async () => {
    const requested: string[] = [];
    globalThis.fetch = async (input) => {
      const url = new URL(String(input));
      requested.push(url.href);
      const host = url.hostname;
      return Response.json({
        authorization_endpoint: `https://${host}/authorize`,
        token_endpoint: `https://${host}/token`,
        jwks_uri: `https://${host}/jwks`,
      });
    };
    const secondConfig: AuthConfig = {
      ...config,
      oidc: { ...config.oidc, issuer: "https://other-idp.example" },
    };

    const first = await discover(config);
    const firstCached = await discover(config);
    const second = await discover(secondConfig);

    assert.equal(first.tokenEndpoint, "https://idp.example/token");
    assert.deepEqual(firstCached, first);
    assert.equal(second.tokenEndpoint, "https://other-idp.example/token");
    assert.deepEqual(requested, [
      "https://idp.example/.well-known/openid-configuration",
      "https://other-idp.example/.well-known/openid-configuration",
    ]);
  });

  it("coalesces concurrent cold discovery requests for one issuer", async () => {
    let calls = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    globalThis.fetch = async (input) => {
      calls += 1;
      await gate;
      const host = new URL(String(input)).hostname;
      return Response.json({
        authorization_endpoint: `https://${host}/authorize`,
        token_endpoint: `https://${host}/token`,
        jwks_uri: `https://${host}/jwks`,
      });
    };

    const pending = Array.from({ length: 8 }, () => discover(config));
    assert.equal(calls, 1);
    release();
    const results = await Promise.all(pending);
    assert.equal(calls, 1);
    assert.ok(results.every((result) => result.tokenEndpoint === "https://idp.example/token"));
  });

  it("does not cache failed discovery and retries on the next request", async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      if (calls === 1) return new Response("unavailable", { status: 503 });
      return Response.json({
        authorization_endpoint: "https://idp.example/authorize",
        token_endpoint: "https://idp.example/token",
        jwks_uri: "https://idp.example/jwks",
      });
    };

    await assert.rejects(discover(config), /issuer returned HTTP 503/);
    const recovered = await discover(config);
    assert.equal(recovered.tokenEndpoint, "https://idp.example/token");
    assert.equal(calls, 2);
  });

  it("reuses the JWKS resolver across login callbacks", async () => {
    const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
    const jwk = await exportJWK(publicKey);
    jwk.kid = "oidc-test-key";
    jwk.alg = "RS256";
    const nonces: string[] = [];
    let tokenCalls = 0;
    let jwksCalls = 0;
    let tokenAudience: string | string[] = config.oidc.clientId;
    let tokenAzp: string | undefined;
    globalThis.fetch = async (input, init) => {
      const url = new URL(String(input));
      if (url.pathname === "/.well-known/openid-configuration") {
        return Response.json({
          authorization_endpoint: "https://idp.example/authorize",
          token_endpoint: "https://idp.example/token",
          jwks_uri: "https://idp.example/jwks",
        });
      }
      if (url.pathname === "/token" && init?.method === "POST") {
        const nonce = nonces[tokenCalls++];
        const claims = {
          sub: "oidc-user",
          nonce,
          ...(tokenAzp === undefined ? {} : { azp: tokenAzp }),
        };
        const idToken = await new SignJWT(claims)
          .setProtectedHeader({ alg: "RS256", kid: "oidc-test-key" })
          .setIssuer(config.oidc.issuer)
          .setAudience(tokenAudience)
          .setIssuedAt()
          .setExpirationTime("5m")
          .sign(privateKey);
        return Response.json({ id_token: idToken });
      }
      if (url.pathname === "/jwks") {
        jwksCalls += 1;
        return Response.json({ keys: [jwk] });
      }
      throw new Error(`unexpected OIDC request: ${url.href}`);
    };

    const redirectUri = "https://console.example/api/auth/callback";
    const first = await buildLoginRedirect(config, redirectUri);
    const firstState = (await jwtVerify(first.stateJwt, config.sessionSecret)).payload;
    const second = await buildLoginRedirect(config, redirectUri);
    const secondState = (await jwtVerify(second.stateJwt, config.sessionSecret)).payload;
    nonces.push(String(firstState.nonce), String(secondState.nonce));

    const complete = async (
      login: Awaited<ReturnType<typeof buildLoginRedirect>>,
      code: string,
    ) => {
      const state = new URL(login.authorizeUrl).searchParams.get("state");
      return completeLogin(
        config,
        new URLSearchParams({ code, state: state ?? "" }),
        login.stateJwt,
        redirectUri,
      );
    };
    assert.equal((await complete(first, "first-code")).sub, "oidc-user");
    assert.equal((await complete(second, "second-code")).sub, "oidc-user");

    const multiAudienceLogin = await buildLoginRedirect(config, redirectUri);
    const multiAudienceState = (await jwtVerify(multiAudienceLogin.stateJwt, config.sessionSecret)).payload;
    nonces.push(String(multiAudienceState.nonce));
    tokenAudience = [config.oidc.clientId, "another-client"];
    await assert.rejects(complete(multiAudienceLogin, "missing-azp"), /authorized party mismatch/);

    const mismatchedAzpLogin = await buildLoginRedirect(config, redirectUri);
    const mismatchedAzpState = (await jwtVerify(mismatchedAzpLogin.stateJwt, config.sessionSecret)).payload;
    nonces.push(String(mismatchedAzpState.nonce));
    tokenAzp = "another-client";
    await assert.rejects(complete(mismatchedAzpLogin, "mismatched-azp"), /authorized party mismatch/);

    const singleAudienceLogin = await buildLoginRedirect(config, redirectUri);
    const singleAudienceState = (await jwtVerify(singleAudienceLogin.stateJwt, config.sessionSecret)).payload;
    nonces.push(String(singleAudienceState.nonce));
    tokenAudience = config.oidc.clientId;
    await assert.rejects(complete(singleAudienceLogin, "single-audience-mismatched-azp"), /authorized party mismatch/);

    const validAzpLogin = await buildLoginRedirect(config, redirectUri);
    const validAzpState = (await jwtVerify(validAzpLogin.stateJwt, config.sessionSecret)).payload;
    nonces.push(String(validAzpState.nonce));
    tokenAzp = config.oidc.clientId;
    assert.equal((await complete(validAzpLogin, "valid-azp")).sub, "oidc-user");
    assert.equal(tokenCalls, 6);
    assert.equal(jwksCalls, 1, "the cached jose resolver reuses the fetched key set");
  });
});
