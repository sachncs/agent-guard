import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { exportJWK, generateKeyPair, SignJWT, jwtVerify } from "jose";
import type { AuthConfig } from "./config.ts";
import {
  buildLoginRedirect,
  completeLogin,
  discover,
  LoginFailed,
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
  sessionTtlSeconds: 8 * 60 * 60,
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

  it("rejects oversized discovery responses before parsing", async () => {
    globalThis.fetch = async () => new Response("{}", {
      headers: { "content-length": String(64 * 1024 + 1) },
    });
    await assert.rejects(discover(config), {
      name: OidcError.name,
      message: "discovery document is invalid or exceeds the size limit",
    });
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
    let tokenSubject = "oidc-user";
    let includeIssuedAt = true;
    let includeExpiration = true;
    let issuedAtOffsetSeconds = 0;
    let oversizedTokenResponse = false;
    let oversizedJwksResponse = false;
    const tokenNonceOverride: { value?: string } = {};
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
        if (oversizedTokenResponse) {
          return new Response("{}", {
            headers: { "content-length": String(256 * 1024 + 1) },
          });
        }
        const nonce = tokenNonceOverride.value ?? nonces[tokenCalls];
        tokenCalls += 1;
        const claims = {
          sub: tokenSubject,
          nonce,
          ...(tokenAzp === undefined ? {} : { azp: tokenAzp }),
        };
        let token = new SignJWT(claims)
          .setProtectedHeader({ alg: "RS256", kid: "oidc-test-key" })
          .setIssuer(config.oidc.issuer)
          .setAudience(tokenAudience);
        if (includeIssuedAt) {
          token = token.setIssuedAt(Math.floor(Date.now() / 1000) + issuedAtOffsetSeconds);
        }
        if (includeExpiration) token = token.setExpirationTime("5m");
        const idToken = await token.sign(privateKey);
        return Response.json({ id_token: idToken });
      }
      if (url.pathname === "/jwks") {
        jwksCalls += 1;
        if (oversizedJwksResponse) {
          return new Response("{}", {
            headers: { "content-length": String(256 * 1024 + 1) },
          });
        }
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
    const oversizedLogin = await buildLoginRedirect(config, redirectUri);
    oversizedTokenResponse = true;
    await assert.rejects(
      complete(oversizedLogin, "oversized-token"),
      (error: unknown) => error instanceof LoginFailed && error.message === "token endpoint returned an invalid response",
    );
    oversizedTokenResponse = false;
    assert.equal((await complete(first, "first-code")).sub, "oidc-user");
    assert.equal((await complete(second, "second-code")).sub, "oidc-user");

    const missingExpirationLogin = await buildLoginRedirect(config, redirectUri);
    const missingExpirationState = (await jwtVerify(missingExpirationLogin.stateJwt, config.sessionSecret)).payload;
    nonces.push(String(missingExpirationState.nonce));
    includeExpiration = false;
    await assert.rejects(complete(missingExpirationLogin, "missing-exp"), /ID token validation failed/);
    includeExpiration = true;

    const missingIssuedAtLogin = await buildLoginRedirect(config, redirectUri);
    const missingIssuedAtState = (await jwtVerify(missingIssuedAtLogin.stateJwt, config.sessionSecret)).payload;
    nonces.push(String(missingIssuedAtState.nonce));
    includeIssuedAt = false;
    await assert.rejects(complete(missingIssuedAtLogin, "missing-iat"), /ID token validation failed/);
    includeIssuedAt = true;

    const staleTokenLogin = await buildLoginRedirect(config, redirectUri);
    const staleTokenState = (await jwtVerify(staleTokenLogin.stateJwt, config.sessionSecret)).payload;
    nonces.push(String(staleTokenState.nonce));
    issuedAtOffsetSeconds = -12 * 60;
    await assert.rejects(complete(staleTokenLogin, "stale-token"), /ID token validation failed/);
    issuedAtOffsetSeconds = 0;

    const futureTokenLogin = await buildLoginRedirect(config, redirectUri);
    const futureTokenState = (await jwtVerify(futureTokenLogin.stateJwt, config.sessionSecret)).payload;
    nonces.push(String(futureTokenState.nonce));
    issuedAtOffsetSeconds = 2 * 60;
    await assert.rejects(complete(futureTokenLogin, "future-token"), /ID token validation failed/);
    issuedAtOffsetSeconds = 0;

    const emptySubjectLogin = await buildLoginRedirect(config, redirectUri);
    const emptySubjectState = (await jwtVerify(emptySubjectLogin.stateJwt, config.sessionSecret)).payload;
    nonces.push(String(emptySubjectState.nonce));
    tokenSubject = "";
    await assert.rejects(complete(emptySubjectLogin, "empty-sub"), /invalid sub claim/);
    tokenSubject = "oidc-user";

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
    assert.equal(tokenCalls, 11);
    assert.equal(jwksCalls, 1, "the cached jose resolver reuses the fetched key set");

    resetDiscoveryCache();
    const oversizedJwksLogin = await buildLoginRedirect(config, redirectUri);
    const oversizedJwksState = (await jwtVerify(oversizedJwksLogin.stateJwt, config.sessionSecret)).payload;
    tokenNonceOverride.value = String(oversizedJwksState.nonce);
    oversizedJwksResponse = true;
    await assert.rejects(complete(oversizedJwksLogin, "oversized-jwks"), /ID token validation failed/);
    oversizedJwksResponse = false;
    assert.equal((await complete(oversizedJwksLogin, "jwks-retry")).sub, "oidc-user");
    assert.equal(jwksCalls, 3, "an oversized JWKS is rejected and a later request can retry");
  });
});
