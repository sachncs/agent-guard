#!/usr/bin/env node
/**
 * End-to-end authentication proof for the agentguard console.
 *
 * Boots loopback test services, then drives the PRODUCTION Next.js build:
 *   - mock OIDC IdP (RS256 tokens, PKCE, nonce, discovery)
 *   - mock AuthZEN PDP
 *   - Redis-compatible REST store for production sessions and rate limits
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
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import https from "node:https";
import http from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

const FRONTEND_PORT = 3171;
const IDP_PORT = 3172;
const PDP_PORT = 3173;
const REDIS_PORT = 3174;
const BASE = `http://127.0.0.1:${FRONTEND_PORT}`;
const ISSUER = `https://127.0.0.1:${IDP_PORT}`;
const REDIS_URL = `https://127.0.0.1:${REDIS_PORT}`;
const REDIS_TOKEN = "e2e-redis-token";
const TEST_CLIENT_IP = "198.51.100.42";
const REAL_PDP = process.env.AGENTGUARD_E2E_REAL_PDP === "1";
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function createTestTls(tlsDir) {
  const keyPath = join(tlsDir, "test-key.pem");
  const certPath = join(tlsDir, "test-cert.pem");
  const cert = spawnSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyPath,
    "-out", certPath, "-days", "1", "-subj", "/CN=127.0.0.1",
    "-addext", "subjectAltName=IP:127.0.0.1",
  ], { stdio: "ignore" });
  assert.equal(cert.status, 0, "OpenSSL creates the local HTTPS test certificate");
  return { key: readFileSync(keyPath), cert: readFileSync(certPath), certPath };
}

// ---------------------------------------------------------------- fake IdP

const idpCodes = new Map(); // code -> { claims, nonce }

const VIEWER_CLAIMS = { sub: "viewer-user", email: "viewer@example.com", groups: ["everyone"] };
const ADMIN_CLAIMS = { sub: "admin-user", email: "admin@example.com", groups: ["agentguard-admins"] };

async function startIdp(tls) {
  let discoveryAvailable = true;
  const { publicKey, privateKey } = await generateKeyPair("RS256", {
    extractable: true,
  });
  const publicJwk = structuredClone(await exportJWK(publicKey));
  publicJwk.kid = "e2e-key";
  publicJwk.alg = "RS256";
  const privateKeyImported = privateKey;

  const server = https.createServer(tls, async (req, res) => {
    const url = new URL(req.url, ISSUER);
    if (url.pathname === "/.well-known/openid-configuration") {
      if (!discoveryAvailable) {
        res.writeHead(503, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "private issuer diagnostic" }));
        return;
      }
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
  return {
    server,
    setDiscoveryAvailable(value) {
      discoveryAvailable = value;
    },
  };
}

// ---------------------------------------------------------------- fake PDP

async function startPdp() {
  if (REAL_PDP) return startRealPdp();

  let responseMode = "decision";
  let lastEvaluation;
  const server = http.createServer((req, res) => {
    if (req.method === "GET" && req.url === "/readyz") {
      res.writeHead(responseMode === "unavailable" ? 503 : 200).end();
      return;
    }
    if (req.method !== "POST" || !req.url.includes("/access/v1/evaluation")) {
      res.writeHead(404).end();
      return;
    }
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      if (responseMode === "unavailable") {
        res.writeHead(503, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "maintenance" }));
        return;
      }
      if (responseMode === "invalid") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ decision: "allow" }));
        return;
      }

      const evaluation = JSON.parse(body);
      lastEvaluation = evaluation;
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
  return {
    bearer: "e2e-console-bearer",
    close: () => new Promise((resolve) => server.close(resolve)),
    setResponseMode(mode) {
      responseMode = mode;
    },
    lastEvaluation() {
      return structuredClone(lastEvaluation);
    },
  };
}

async function startRealPdp() {
  const dir = mkdtempSync(join(tmpdir(), "agentguard-real-pdp-"));
  const store = join(dir, "store");
  const policies = join(store, "policies");
  mkdirSync(policies, { recursive: true });
  copyFileSync(join(REPO_ROOT, "schemas/starter.cedarschema"), join(store, "schema.cedarschema"));
  writeFileSync(join(policies, "10_e2e.cedar"), `permit (
  principal == Agent::"research",
  action == Action::"ToolCall::repo_read",
  resource == Repository::"demo"
) when {
  context.repo == "demo" &&
  context.session has ip &&
  context.session.ip == "127.0.0.1"
};\n`);
  const auditPath = join(dir, "audit.jsonl");
  const secretPath = join(dir, "chain-secret");
  const keyStorePath = join(dir, "keys.json");
  writeFileSync(secretPath, "real-pdp-e2e-chain-secret", { mode: 0o600 });
  const cli = process.env.AGENTGUARD_PDP_CLI_BIN
    ?? join(REPO_ROOT, "target/debug/agentguard");
  const keyCreation = spawnSync(cli, [
    "--output", "json", "api-key", "create", "--key-store", keyStorePath,
    "--subject-type", "Agent", "--subject-id", "console-service",
    "--scope", "authorize:any",
  ], { cwd: REPO_ROOT, encoding: "utf8" });
  assert.equal(keyCreation.status, 0, `create scoped console API key: ${keyCreation.stderr}`);
  const key = JSON.parse(keyCreation.stdout);
  const bearer = key.raw_secret;
  assert.ok(bearer, "the real PDP test creates a bound authorize:any service key");
  const binary = process.env.AGENTGUARD_SERVER_BIN
    ?? join(REPO_ROOT, "target/debug/agentguard-server");
  let child;
  let output = "";
  let spawnError;

  const start = async () => {
    child = spawn(binary, [], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        AGENTGUARD_LISTEN: `tcp://127.0.0.1:${PDP_PORT}`,
        AGENTGUARD_STORE: store,
        AGENTGUARD_AUDIT: auditPath,
        AGENTGUARD_CHAIN_SECRET: secretPath,
        AGENTGUARD_AUTH: `apikey:${keyStorePath}`,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    child.once("error", (error) => {
      spawnError = error;
      output += `${error}\n`;
    });
    child.stdout.on("data", (data) => {
      output += data;
      if (process.env.E2E_DEBUG) process.stdout.write(data);
    });
    child.stderr.on("data", (data) => {
      output += data;
      if (process.env.E2E_DEBUG) process.stderr.write(data);
    });

    for (let attempt = 0; attempt < 100; attempt++) {
      if (spawnError) throw new Error(`could not start real PDP: ${spawnError.message}`);
      if (child.exitCode !== null) {
        throw new Error(`real PDP exited before readiness (${child.exitCode}):\n${output}`);
      }
      try {
        const response = await fetch(`http://127.0.0.1:${PDP_PORT}/readyz`, {
          signal: AbortSignal.timeout(500),
        });
        if (response.status === 200) return;
      } catch {}
      await sleep(100);
    }
    throw new Error(`real PDP did not become ready:\n${output}`);
  };

  const stop = async () => {
    if (!child) return;
    const current = child;
    child = undefined;
    if (current.exitCode !== null) return;
    await new Promise((resolve) => {
      const timer = setTimeout(() => {
        current.kill("SIGKILL");
        resolve();
      }, 5_000);
      current.once("exit", () => {
        clearTimeout(timer);
        resolve();
      });
      current.kill("SIGTERM");
    });
  };

  try {
    await start();
    const unauthenticated = await fetch(`http://127.0.0.1:${PDP_PORT}/access/v1/evaluation`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    assert.equal(unauthenticated.status, 401, "real PDP protects evaluations without a bearer");
  } catch (error) {
    await stop();
    rmSync(dir, { recursive: true, force: true });
    throw error;
  }

  return {
    auditPath,
    bearer,
    credentialId: key.id,
    async start() {
      output = "";
      spawnError = undefined;
      await start();
    },
    stop,
    async close() {
      await stop();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

// -------------------------------------------- Redis-compatible REST store

async function startRedisRest(tls) {
  const sessions = new Map();
  const rateWindows = new Map();
  let available = true;
  const server = https.createServer(tls, async (req, res) => {
    if (!available) {
      res.writeHead(503).end();
      return;
    }
    if (req.method !== "POST") {
      res.writeHead(405).end();
      return;
    }
    if (req.headers.authorization !== `Bearer ${REDIS_TOKEN}`) {
      res.writeHead(401).end();
      return;
    }

    let body = "";
    for await (const chunk of req) body += chunk;
    let command;
    try {
      command = JSON.parse(body);
    } catch {
      res.writeHead(400).end();
      return;
    }

    let result;
    if (command[0] === "PING") {
      result = "PONG";
    } else if (command[0] === "SET" && command[3] === "EX") {
      sessions.set(command[1], {
        value: command[2],
        expiresAt: Date.now() + Number(command[4]) * 1000,
      });
      result = "OK";
    } else if (command[0] === "GET") {
      const stored = sessions.get(command[1]);
      if (stored && stored.expiresAt <= Date.now()) sessions.delete(command[1]);
      result = stored && stored.expiresAt > Date.now() ? stored.value : null;
    } else if (command[0] === "DEL") {
      result = sessions.delete(command[1]) ? 1 : 0;
    } else if (command[0] === "EVAL" && command[2] === "1") {
      const key = command[3];
      const windowMs = Number(command[4]) * 1000;
      const previous = rateWindows.get(key);
      const bucket = !previous || previous.expiresAt <= Date.now()
        ? { count: 0, expiresAt: Date.now() + windowMs }
        : previous;
      bucket.count += 1;
      rateWindows.set(key, bucket);
      result = bucket.count;
    } else {
      res.writeHead(400).end();
      return;
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ result }));
  });
  await new Promise((r) => server.listen(REDIS_PORT, "127.0.0.1", r));
  return {
    server,
    setAvailable(value) {
      available = value;
    },
  };
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
  if (!Object.keys(headers).some((name) => name.toLowerCase() === "x-forwarded-for")) {
    // Model the trusted ingress replacing the untrusted incoming header.
    headers["X-Forwarded-For"] = TEST_CLIENT_IP;
  }
  if (jar && jar.header()) headers.Cookie = jar.header();
  const url = path.startsWith("http") ? path : `${BASE}${path}`;
  const res = await fetch(url, { ...init, headers, redirect: "manual" });
  if (jar) jar.absorb(res);
  return res;
}

function fetchIdp(url, ca) {
  return new Promise((resolve, reject) => {
    const request = https.request(url, { method: "GET", ca, rejectUnauthorized: true }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => {
        const headers = Object.fromEntries(
          Object.entries(response.headers)
            .filter(([, value]) => value !== undefined)
            .map(([name, value]) => [name, Array.isArray(value) ? value.join(", ") : value]),
        );
        resolve(new Response(Buffer.concat(chunks), {
          status: response.statusCode,
          headers,
        }));
      });
    });
    request.on("error", reject);
    request.end();
  });
}

/** Drives the full OIDC dance against the mock IdP. */
async function login(as, jar, ca) {
  const start = await req(jar, "/api/auth/login");
  assert.equal(start.status, 302, "login redirects to IdP");
  const authorizeUrl = new URL(start.headers.get("location"), BASE);
  assert.equal(authorizeUrl.origin, ISSUER);
  assert.equal(authorizeUrl.searchParams.get("code_challenge_method"), "S256");
  if (as) authorizeUrl.searchParams.set("as", as);
  const idpRes = await fetchIdp(authorizeUrl, ca);
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
  const tlsDir = mkdtempSync(join(tmpdir(), "ag-e2e-tls-"));
  const tls = createTestTls(tlsDir);
  const idp = await startIdp(tls);
  const pdp = await startPdp();
  const redis = await startRedisRest(tls);

  const env = {
    ...process.env,
    PORT: String(FRONTEND_PORT),
    HOSTNAME: "127.0.0.1",
    AGENTGUARD_OIDC_ISSUER: ISSUER,
    AGENTGUARD_OIDC_CLIENT_ID: "agentguard-console",
    AGENTGUARD_OIDC_CLIENT_SECRET: "e2e-client-secret",
    AGENTGUARD_SESSION_SECRET: "s".repeat(48),
    AGENTGUARD_SESSION_STORE: "redis",
    AGENTGUARD_SESSION_REDIS_URL: REDIS_URL,
    AGENTGUARD_SESSION_REDIS_TOKEN: REDIS_TOKEN,
    AGENTGUARD_RATE_LIMIT_STORE: "redis",
    AGENTGUARD_RATE_LIMIT_REDIS_URL: REDIS_URL,
    AGENTGUARD_RATE_LIMIT_REDIS_TOKEN: REDIS_TOKEN,
    NODE_EXTRA_CA_CERTS: tls.certPath,
    AGENTGUARD_ADMIN_VALUES: "agentguard-admins",
    AGENTGUARD_TRUST_PROXY_HEADERS: "1",
    AGENTGUARD_PDP_URL: `http://127.0.0.1:${PDP_PORT}`,
    AGENTGUARD_PDP_ALLOW_INSECURE_INTERNAL: "1",
    AGENTGUARD_PDP_BEARER: pdp.bearer,
    AGENTGUARD_INSECURE_COOKIE: "1",
    AGENTGUARD_BIN: fakeBin,
    AGENTGUARD_DELEGATION_KEY_FILE: "/tmp/e2e-delegation.key",
  };

  console.log("starting production build…");
  const build = spawnSync("pnpm", ["exec", "next", "build", "--webpack"], { cwd: process.cwd(), stdio: "inherit" });
  assert.equal(build.status, 0, "next build succeeds");

  const app = spawn(process.execPath, [".next/standalone/frontend/server.js"], {
    cwd: process.cwd(),
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  app.stderr.on("data", (d) => process.env.E2E_DEBUG && process.stderr.write(d));
  try {
    await waitForApp();

    assert.equal((await fetch(`${BASE}/api/health/live`)).status, 200);
    assert.equal((await fetch(`${BASE}/api/health/ready`)).status, 200);

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

    idp.setDiscoveryAvailable(false);
    const idpFailure = await req(new Jar(), "/api/auth/login");
    assert.equal(idpFailure.status, 502, "OIDC discovery failures return a gateway error");
    const idpFailureBody = await idpFailure.json();
    assert.equal(idpFailureBody.kind, "idp_error");
    assert.equal(
      idpFailureBody.error,
      "The identity provider is temporarily unavailable. Try again shortly."
    );
    assert.match(idpFailureBody.reference, /^[0-9a-f-]{36}$/);
    assert.doesNotMatch(JSON.stringify(idpFailureBody), /private issuer diagnostic/);
    idp.setDiscoveryAvailable(true);

    // --- 2. viewer login -------------------------------------------------
    const viewer = new Jar();
    await login(null, viewer, tls.cert);
    assert.match(viewer.header(), /ag_session=/, "session cookie issued");

    const viewerRoot = await req(viewer, "/");
    assert.equal(viewerRoot.status, 200);
    const html = await viewerRoot.text();
    assert.match(html, /viewer@example.com/, "nav shows identity");
    assert.match(html, /aria-label="Mobile console navigation"/, "responsive navigation is present");
    assert.equal(html.includes(pdp.bearer), false, "PDP credential is never rendered into browser HTML");
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
        uid: "research", principalType: "agent", tool: "repo_read",
        resourceType: "Repository", resourceId: "demo",
        args: { repo: "demo", session: { ip: "spoofed" } },
        session: { ip: "127.0.0.1" },
      }),
    });
    assert.equal(allowRes.status, 200);
    const allowDecision = await allowRes.json();
    assert.equal(allowDecision.effect, "allow");
    if (!REAL_PDP) {
      assert.deepEqual(allowDecision.reasons, ["explicit permit"]);
      assert.deepEqual(pdp.lastEvaluation().context, {
        repo: "demo",
        session: { ip: "127.0.0.1" },
      }, "console flattens Cedar context args and prevents session spoofing");
    }

    const denyRes = await req(viewer, "/api/authorize", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        uid: "research", principalType: "agent", tool: "repo_read",
        resourceType: "Repository", resourceId: "forbidden",
        args: { repo: "demo" }, session: { ip: "127.0.0.1" },
      }),
    });
    const denyDecision = await denyRes.json();
    assert.equal(denyDecision.effect, "deny");

    if (REAL_PDP) {
      const records = readFileSync(pdp.auditPath, "utf8").trim().split("\n").map(JSON.parse);
      assert.equal(records.length, 2, "allow and deny decisions are durably audited");
      assert.deepEqual(records.map((record) => record.effect), ["allow", "deny"]);
      assert.ok(records.every((record) => record.record_hash && record.chain_id),
        "audit records include chained-integrity metadata");
      assert.ok(records.every((record) =>
        record.authenticated_actor?.subject_type === "Agent" &&
        record.authenticated_actor.subject_id === "console-service" &&
        record.authenticated_actor.credential_id === pdp.credentialId &&
        record.authenticated_actor.can_act_as === true),
      "audit records attribute act-as decisions to the bound service and key");

      await pdp.stop();
      const stoppedPdp = await req(viewer, "/api/authorize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          uid: "research", principalType: "agent", tool: "repo_read",
          resourceType: "Repository", resourceId: "demo", args: { repo: "demo" },
          session: { ip: "127.0.0.1" },
        }),
      });
      assert.equal(stoppedPdp.status, 503, "PDP outage fails authorization closed");
      assert.equal((await fetch(`${BASE}/api/health/ready`)).status, 503,
        "readiness fails while real PDP is stopped");
      await pdp.start();
      assert.equal((await fetch(`${BASE}/api/health/ready`)).status, 200,
        "readiness recovers after real PDP restart");
    } else {
    // PDP failures must never be converted into an authorization decision.
    pdp.setResponseMode("unavailable");
    const unavailablePdp = await req(viewer, "/api/authorize", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        uid: "alice", tool: "web_search", resourceType: "Resource", resourceId: "docs",
      }),
    });
    assert.equal(unavailablePdp.status, 503, "PDP HTTP failures return service unavailable");
    const unavailableBody = await unavailablePdp.json();
    assert.equal(unavailableBody.kind, "pdp_unavailable");
    assert.equal(
      unavailableBody.error,
      "The authorization service is temporarily unavailable."
    );
    assert.match(unavailableBody.reference, /^[0-9a-f-]{36}$/);
    assert.doesNotMatch(JSON.stringify(unavailableBody), /maintenance|PDP returned HTTP/);
    assert.equal((await fetch(`${BASE}/api/health/ready`)).status, 503,
      "readiness fails when the required PDP is unavailable");

    pdp.setResponseMode("invalid");
    const invalidPdp = await req(viewer, "/api/authorize", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        uid: "alice", tool: "web_search", resourceType: "Resource", resourceId: "docs",
      }),
    });
    assert.equal(invalidPdp.status, 503, "malformed PDP decisions fail closed");
    const invalidPdpBody = await invalidPdp.json();
    assert.equal(invalidPdpBody.kind, "pdp_unavailable");
    assert.equal(
      invalidPdpBody.error,
      "The authorization service is temporarily unavailable."
    );
    assert.match(invalidPdpBody.reference, /^[0-9a-f-]{36}$/);
    pdp.setResponseMode("decision");
    assert.equal((await fetch(`${BASE}/api/health/ready`)).status, 200,
      "readiness recovers when the PDP recovers");
    }

    const invalidAuthz = await req(viewer, "/api/authorize", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ uid: "-evil", tool: "x", resourceType: "R", resourceId: "b" }),
    });
    assert.equal(invalidAuthz.status, 400, "option-looking uid rejected");

    // --- 5. admin login + delegation --------------------------------------
    const admin = new Jar();
    await login("admin", admin, tls.cert);
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
    const delegationPage = await req(admin, "/delegation");
    assert.equal(delegationPage.status, 200, "admin can open delegation tools");
    assert.match(
      await delegationPage.text(),
      /they do not authorize a tool call or enforce/
    );

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

    if (!REAL_PDP) {
      let simulatorRateLimited = false;
      for (let i = 0; i < 61; i++) {
        const response = await req(viewer, "/api/authorize", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            uid: "alice", tool: "web_search", resourceType: "Resource",
            resourceId: `rate-${i}`,
          }),
        });
        if (response.status === 429) {
          simulatorRateLimited = true;
          break;
        }
        assert.equal(response.status, 200);
      }
      assert.ok(simulatorRateLimited, "simulator rate limit trips before exhausting PDP capacity");
    }

    // --- 7. logout ---------------------------------------------------------
    const logout = await req(admin, "/api/auth/logout");
    assert.equal(logout.status, 302);
    const afterLogout = await req(admin, "/api/log");
    assert.equal(afterLogout.status, 401, "session dead after logout");

    redis.setAvailable(false);
    assert.equal((await fetch(`${BASE}/api/health/ready`)).status, 503,
      "readiness fails when shared stores are unavailable");
    redis.setAvailable(true);
    assert.equal((await fetch(`${BASE}/api/health/ready`)).status, 200,
      "readiness recovers when shared stores recover");

    console.log("\nALL E2E ASSERTIONS PASSED");
  } finally {
    app.kill("SIGTERM");
    idp.server.close();
    await pdp.close();
    redis.server.close();
    rmSync(tlsDir, { recursive: true, force: true });
  }

  // --- 8. fail-closed without configuration -------------------------------
  console.log("checking fail-closed posture (no auth env)…");
  const bareEnv = { ...process.env };
  for (const k of Object.keys(env)) {
    if (k.startsWith("AGENTGUARD_")) delete bareEnv[k];
  }
  const barePort = 3181;
  const bare = spawn(process.execPath, [".next/standalone/frontend/server.js"], {
    cwd: process.cwd(),
    env: { ...bareEnv, PORT: String(barePort), HOSTNAME: "127.0.0.1" },
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
    assert.equal((await fetch(`http://127.0.0.1:${barePort}/api/health/live`)).status, 200);
    assert.equal((await fetch(`http://127.0.0.1:${barePort}/api/health/ready`)).status, 503);
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
