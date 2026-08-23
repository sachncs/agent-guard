#!/usr/bin/env node
/**
 * End-to-end authentication proof for the agentguard console.
 *
 * Boots three fakes on loopback, then drives the PRODUCTION Next.js build:
 *   - mock OIDC IdP (RS256 tokens, PKCE, nonce, discovery)
 *   - mock AuthZEN PDP
 *   - fake `agentguard` CLI (for log/delegate/verify routes)
 *
 * Asserts the full security posture:
 *   1. Unauthenticated pages redirect to /login, APIs answer 401
 *   2. Full OIDC login round-trip issues a working session cookie
 *   3. RBAC: viewers cannot delegate/verify (403), admins can
 *   4. Validation errors return 400, rate limits return 429
 *   5. Simulator decisions come from the PDP over HTTP
 *   6. Without auth configuration the whole console fails closed (503)
 *
 * Run: pnpm --filter frontend exec node scripts/e2e.mjs
 */

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, chmodSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

const FRONTEND_PORT = 3171;
const IDP_PORT = 3172;
const PDP_PORT = 3173;
const BASE = `http://127.0.0.1:${FRONTEND_PORT}`;
const ISSUER = `http://127.0.0.1:${IDP_PORT}`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------- fake IdP

const idpCodes = new Map(); // code -> { claims, nonce }

const VIEWER_CLAIMS = { sub: "viewer-user", email: "viewer@example.com", groups: ["everyone"] };
const ADMIN_CLAIMS = { sub: "admin-user", email: "admin@example.com", groups: ["agentguard-admins"] };

async function startIdp() {
  const { publicKey, privateKey } = await generateKeyPair("RS256", {
    extractable: true,
  });
  const publicJwk = structuredClone(await exportJWK(publicKey));
  publicJwk.kid = "e2e-key";
  publicJwk.alg = "RS256";
  const privateKeyImported = privateKey;

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, ISSUER);
    if (url.pathname === "/.well-known/openid-configuration") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/jwks.json`,
        })
      );
      return;
    }
    if (url.pathname === "/jwks.json") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ keys: [publicJwk] }));
      return;
    }
    if (url.pathname === "/authorize") {
      // Skip real credentials: mint a code immediately. `as` picks the claim set.
      const code = Math.random().toString(36).slice(2);
      idpCodes.set(code, {
        claims: url.searchParams.get("as") === "admin" ? ADMIN_CLAIMS : VIEWER_CLAIMS,
        nonce: url.searchParams.get("nonce"),
      });
      const back = new URL(url.searchParams.get("redirect_uri"));
      back.searchParams.set("code", code);
      back.searchParams.set("state", url.searchParams.get("state"));
      res.writeHead(302, { Location: back.toString() });
      res.end();
      return;
    }
    if (url.pathname === "/token" && req.method === "POST") {
      let body = "";
      for await (const chunk of req) body += chunk;
      const form = new URLSearchParams(body);
      const record = idpCodes.get(form.get("code"));
      if (!record || form.get("grant_type") !== "authorization_code") {
        res.writeHead(400).end();
        return;
      }
      idpCodes.delete(form.get("code"));
      const idToken = await new SignJWT({ ...record.claims, nonce: record.nonce })
        .setProtectedHeader({ alg: "RS256", kid: "e2e-key" })
        .setIssuer(ISSUER)
        .setAudience(form.get("client_id"))
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(privateKeyImported);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: "at", token_type: "Bearer", id_token: idToken }));
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((r) => server.listen(IDP_PORT, "127.0.0.1", r));
  return server;
}

// ---------------------------------------------------------------- fake PDP

async function startPdp() {
  const server = http.createServer((req, res) => {
    if (req.method !== "POST" || !req.url.includes("/access/v1/evaluation")) {
      res.writeHead(404).end();
      return;
    }
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const evaluation = JSON.parse(body);
      const allowed = evaluation.resource?.id !== "forbidden";
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          decision: allowed,
          reason: allowed ? "explicit permit" : "explicit forbid",
        })
      );
    });
  });
  await new Promise((r) => server.listen(PDP_PORT, "127.0.0.1", r));
  return server;
}

// -------------------------------------------------------------- fake CLI

function writeFakeCli() {
  const dir = mkdtempSync(join(tmpdir(), "ag-e2e-"));
  const bin = join(dir, "agentguard");
  writeFileSync(
    bin,
    `#!/bin/sh
case "$*" in
  *"log tail"*)
    echo '[{"id":"rec-1","timestamp":"2026-01-01T00:00:00Z","effect":"allow","policies":["p1"],"principal":"User::\\"alice\\"","action":"ToolCall::web_search","resource":"Resource::\\"agent\\"","reasons":["permit"]}]' ;;
  *delegate*)
    echo "fake.jwt.token" ;;
  *verify*)
    echo '{"valid":true,"sub":"alice"}' ;;
  *)
    echo 'unexpected invocation: $*' >&2; exit 3 ;;
esac
`
  );
  chmodSync(bin, 0o755);
  return bin;
}

// ------------------------------------------------------------- HTTP client

class Jar {
  cookies = new Map();
  absorb(res) {
    const set = res.headers.getSetCookie?.() ?? [];
    for (const header of set) {
      const [pair] = header.split(";");
      const eq = pair.indexOf("=");
      this.cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
    }
  }
  header() {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  }
  clear(name) {
    this.cookies.delete(name);
  }
}

async function req(jar, path, init = {}) {
  const headers = { ...(init.headers ?? {}) };
  if (jar && jar.header()) headers.Cookie = jar.header();
  const url = path.startsWith("http") ? path : `${BASE}${path}`;
  const res = await fetch(url, { ...init, headers, redirect: "manual" });
  if (jar) jar.absorb(res);
  return res;
}

/** Drives the full OIDC dance against the mock IdP. */
async function login(as, jar) {
  const start = await req(jar, "/api/auth/login");
  assert.equal(start.status, 302, "login redirects to IdP");
  const authorizeUrl = new URL(start.headers.get("location"), BASE);
  assert.equal(authorizeUrl.origin, ISSUER);
  assert.equal(authorizeUrl.searchParams.get("code_challenge_method"), "S256");
  if (as) authorizeUrl.searchParams.set("as", as);
  const idpRes = await fetch(authorizeUrl, { redirect: "manual" });
  jar.absorb(idpRes);
  const callbackUrl = idpRes.headers.get("location");
  assert.ok(callbackUrl.includes("/api/auth/callback"));
  const cb = await req(jar, callbackUrl);
  assert.equal(cb.status, 302, "callback sets session and redirects home");
  assert.equal(new URL(cb.headers.get("location"), BASE).pathname, "/");
  return cb;
}

// ------------------------------------------------------------------- main

async function waitForApp() {
  for (let i = 0; i < 100; i++) {
    try {
      const res = await fetch(`${BASE}/login`, { redirect: "manual" });
      if (res.status < 500) return;
    } catch {}
    await sleep(150);
  }
  throw new Error("app did not start");
}

async function main() {
  const fakeBin = writeFakeCli();
  const idpServer = await startIdp();
  const pdpServer = await startPdp();

  const env = {
    ...process.env,
    PORT: String(FRONTEND_PORT),
    HOSTNAME: "127.0.0.1",
    AGENTGUARD_OIDC_ISSUER: ISSUER,
    AGENTGUARD_OIDC_CLIENT_ID: "agentguard-console",
    AGENTGUARD_OIDC_CLIENT_SECRET: "e2e-client-secret",
    AGENTGUARD_SESSION_SECRET: "s".repeat(48),
    AGENTGUARD_ADMIN_VALUES: "agentguard-admins",
    AGENTGUARD_PDP_URL: `http://127.0.0.1:${PDP_PORT}`,
    AGENTGUARD_INSECURE_COOKIE: "1",
    AGENTGUARD_BIN: fakeBin,
  };

  console.log("starting production build…");
  const build = spawnSync("pnpm", ["exec", "next", "build"], { cwd: process.cwd(), stdio: "inherit" });
  assert.equal(build.status, 0, "next build succeeds");

  const app = spawn("pnpm", ["exec", "next", "start", "-p", String(FRONTEND_PORT), "-H", "127.0.0.1"], {
    cwd: process.cwd(),
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  app.stderr.on("data", (d) => process.env.E2E_DEBUG && process.stderr.write(d));
  try {
    await waitForApp();

    // --- 1. unauthenticated posture -------------------------------------
    const anonJar = new Jar();
    const rootRes = await req(anonJar, "/", { headers: {} });
    assert.equal(rootRes.status, 307, "unauthenticated page redirects");
    assert.equal(new URL(rootRes.headers.get("location"), BASE).pathname, "/login");

    const api401 = await req(anonJar, "/api/log");
    assert.equal(api401.status, 401, "unauthenticated API is 401");
    const del401 = await req(anonJar, "/api/delegate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    assert.equal(del401.status, 401);

    // --- 2. viewer login -------------------------------------------------
    const viewer = new Jar();
    await login(null, viewer);
    assert.match(viewer.header(), /ag_session=/, "session cookie issued");

    const viewerRoot = await req(viewer, "/");
    assert.equal(viewerRoot.status, 200);
    const html = await viewerRoot.text();
    assert.match(html, /viewer@example.com/, "nav shows identity");
    assert.doesNotMatch(html, />admin</, "no admin badge for viewer");

    // --- 3. RBAC ---------------------------------------------------------
    const viewerLog = await req(viewer, "/api/log?n=5");
    assert.equal(viewerLog.status, 200, "viewer can read audit tail");
    const viewerRecords = await viewerLog.json();
    assert.equal(viewerRecords.records[0]?.id, "rec-1");

    const viewerDelegate = await req(viewer, "/api/delegate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        from: "alice", to: "bob", actions: ["ToolCall::x"], resources: ["Resource::r"],
        ttlSeconds: 900,
      }),
    });
    assert.equal(viewerDelegate.status, 403, "viewer cannot delegate");

    const viewerVerify = await req(viewer, "/api/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: "t".repeat(32), keysFile: "keys.json" }),
    });
    assert.equal(viewerVerify.status, 403, "viewer cannot verify");

    // --- 4. simulator via HTTP PDP ---------------------------------------
    const allowRes = await req(viewer, "/api/authorize", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        uid: "alice", tool: "web_search", resourceType: "Resource", resourceId: "docs",
      }),
    });
    assert.equal(allowRes.status, 200);
    const allowDecision = await allowRes.json();
    assert.equal(allowDecision.effect, "allow");
    assert.deepEqual(allowDecision.reasons, ["explicit permit"]);

    const denyRes = await req(viewer, "/api/authorize", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        uid: "alice", tool: "send_email", resourceType: "Resource", resourceId: "forbidden",
      }),
    });
    const denyDecision = await denyRes.json();
    assert.equal(denyDecision.effect, "deny");

    const invalidAuthz = await req(viewer, "/api/authorize", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ uid: "-evil", tool: "x", resourceType: "R", resourceId: "b" }),
    });
    assert.equal(invalidAuthz.status, 400, "option-looking uid rejected");

    // --- 5. admin login + delegation --------------------------------------
    const admin = new Jar();
    await login("admin", admin);
    const okDelegate = await req(admin, "/api/delegate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        from: "alice", to: "bob", actions: ["ToolCall::web_search"], resources: ["Resource::r"],
        ttlSeconds: 900,
      }),
    });
    assert.equal(okDelegate.status, 200, "admin can delegate");
    assert.equal((await okDelegate.json()).token, "fake.jwt.token");

    const badTtl = await req(admin, "/api/delegate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        from: "a", to: "b", actions: ["x"], resources: ["y"], ttlSeconds: 99999999,
      }),
    });
    assert.equal(badTtl.status, 400, "ttl bound enforced");

    const verifyRes = await req(admin, "/api/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: "t".repeat(64), keysFile: "keys.json" }),
    });
    assert.equal(verifyRes.status, 200, "admin can verify");

    // --- 6. rate limiting (limit 10/min on delegate) ----------------------
    let saw429 = false;
    for (let i = 0; i < 12; i++) {
      const rlRes = await req(admin, "/api/delegate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          from: "a", to: "b", actions: ["ToolCall::x"], resources: ["Resource::r"],
          ttlSeconds: 900,
        }),
      });
      if (rlRes.status === 429) {
        saw429 = true;
        break;
      }
      assert.equal(rlRes.status, 200);
    }
    assert.ok(saw429, "delegate rate limit trips");

    // --- 7. logout ---------------------------------------------------------
    const logout = await req(admin, "/api/auth/logout");
    assert.equal(logout.status, 302);
    const afterLogout = await req(admin, "/api/log");
    assert.equal(afterLogout.status, 401, "session dead after logout");

    console.log("\nALL E2E ASSERTIONS PASSED");
  } finally {
    app.kill("SIGTERM");
    idpServer.close();
    pdpServer.close();
  }

  // --- 8. fail-closed without configuration -------------------------------
  console.log("checking fail-closed posture (no auth env)…");
  const bareEnv = { ...process.env };
  for (const k of Object.keys(env)) {
    if (k.startsWith("AGENTGUARD_")) delete bareEnv[k];
  }
  const barePort = 3181;
  const bare = spawn("pnpm", ["exec", "next", "start", "-p", String(barePort), "-H", "127.0.0.1"], {
    cwd: process.cwd(),
    env: bareEnv,
    stdio: "ignore",
  });
  try {
    let up = false;
    for (let i = 0; i < 60 && !up; i++) {
      try {
        await fetch(`http://127.0.0.1:${barePort}/`);
        up = true;
      } catch {
        await sleep(150);
      }
    }
    assert.ok(up, "bare instance started");
    const bareRoot = await fetch(`http://127.0.0.1:${barePort}/`);
    assert.equal(bareRoot.status, 503, "pages fail closed without auth config");
    const bareApi = await fetch(`http://127.0.0.1:${barePort}/api/log`);
    assert.equal(bareApi.status, 503, "APIs fail closed without auth config");
    console.log("FAIL-CLOSED VERIFIED");
  } finally {
    bare.kill("SIGTERM");
  }
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error("E2E FAILURE:", err.message, "\n", err.stack);
    process.exit(1);
  }
);
