import { existsSync, readFileSync } from "node:fs";

const files = ["README.md", "CONTRIBUTING.md", "SUPPORT.md", "SECURITY.md", "RELEASE.md", "BRAND.md", "frontend/README.md", "examples/README.md", "examples/strands-tool-authz/src/main.ts"];
const forbidden = ["agentguard_console", "agentguard_ console"];
const forbiddenProductCopy = ["agent-guard docs", "Contributing to agent-guard", "interest in agent-guard", "agent-guard and its users"];
const failures = [];

function requireFile(file) {
  if (!existsSync(file)) failures.push(`missing required public asset: ${file}`);
}

function requireText(file, value) {
  const text = readFileSync(file, "utf8");
  if (!text.includes(value)) failures.push(`${file}: missing required text ${value}`);
}

for (const file of files) {
  const text = readFileSync(file, "utf8");
  for (const value of forbidden) {
    if (text.includes(value)) failures.push(file + ": stale public string " + value);
  }
  for (const value of forbiddenProductCopy) {
    if (text.includes(value)) failures.push(file + ": stale product copy " + value);
  }
}

for (const file of [
  "site/public/agentguard-mark-dark.svg",
  "site/public/agentguard-mark-mono.svg",
  "site/public/agentguard-mark.svg",
  "site/public/agentguard-wordmark.svg",
  "site/public/agentguard-wordmark-dark.svg",
  "site/public/favicon.svg",
  "site/public/og-image.svg",
  "site/public/og-image.png",
  "site/public/brand/concept-boundary.svg",
  "docs/production.md",
  "docs/configuration.md",
  "scripts/k8s-smoke.sh",
  "deploy/k8s/kustomization.yaml",
  ".dockerignore",
]) requireFile(file);

const markAssets = [
  "site/public/favicon.svg",
  "site/public/agentguard-mark-dark.svg",
  "site/public/agentguard-mark-mono.svg",
  "site/public/agentguard-wordmark.svg",
  "site/public/agentguard-wordmark-dark.svg",
  "frontend/public/agentguard-mark.svg",
];
for (const file of markAssets) {
  const svg = readFileSync(file, "utf8");
  if (!svg.includes("<title id=\"title\">AgentGuard</title>")) failures.push(`${file}: missing accessible AgentGuard title`);
  if (!svg.includes("M32 13 42 17.5v12.2")) failures.push(`${file}: missing selected shield-boundary glyph`);
}
if (!readFileSync("site/public/brand/concept-boundary.svg", "utf8").includes("M160 40 195 55v43")) {
  failures.push("site/public/brand/concept-boundary.svg: missing selected shield-boundary concept");
}
const og = readFileSync("site/public/og-image.svg", "utf8");
if (!og.includes("Policy before execution.") || !og.includes("github.com/sachncs/agent-guard")) {
  failures.push("site/public/og-image.svg: missing canonical product positioning");
}
if (!readFileSync("site/src/layouts/base.astro", "utf8").includes("og-image.png")) {
  failures.push("site/src/layouts/base.astro: social metadata must use the PNG preview");
}

requireText("deploy/k8s/pdp.yaml", 'name: AGENTGUARD_AUTH, value: "apikey:/etc/agentguard/keys/keys.json"');
requireText("frontend/Dockerfile", "ARG AGENTGUARD_CLI_IMAGE");
requireText("frontend/Dockerfile", "FROM ${AGENTGUARD_CLI_IMAGE} AS cli-source");
requireText("frontend/Dockerfile", "COPY --from=cli-source");
requireText("frontend/Dockerfile", "ENV AGENTGUARD_BIN=/usr/local/bin/agentguard");
requireText("Dockerfile", "USER 10001:10001");
requireText("Dockerfile", "AGENTGUARD_AUTH=apikey:/etc/agentguard/keys/keys.json");
requireText("Dockerfile", "-p agentguard-server -p agentguard");
requireText("Dockerfile", "/usr/local/bin/agentguard");
requireText("frontend/Dockerfile", "USER 10001:10001");
requireText("frontend/Dockerfile", "node:22.19.0-bookworm-slim");
requireText(".github/workflows/deploy-site.yml", "uses: pnpm/setup@v3");
requireText(".github/workflows/deploy-site.yml", "runtime: node@22.19.0");
requireText(".github/workflows/deploy-site.yml", '- "docs/**"');
requireText(".github/workflows/ci.yml", "runtime: node@22.19.0");
requireText(".github/workflows/ci.yml", "Swatinem/rust-cache@v2");
requireText(".github/workflows/ci.yml", "cargo test -p agentguard-server --all-features");
requireText(".github/workflows/ci.yml", "node scripts/verify-rust-package-metadata.mjs");
requireText(".github/workflows/ci.yml", "cargo llvm-cov report --summary-only --fail-under-lines 80");
requireText(".github/workflows/ci.yml", "pnpm audit:dependencies");
requireText("package.json", "pnpm --dir site audit --audit-level=moderate");
requireText("README.md", "embedded library callers");
requireText("README.md", "The standalone PDP does not consume delegation");
requireText("README.md", "the integration at the tool boundary must verify expiry");
requireText("docs/architecture.md", "Embedded `Authorizer` calls return decisions without");
requireText("scripts/k8s-smoke.sh", "AGENTGUARD_KIND_CLUSTER");
requireText("scripts/k8s-smoke.sh", "agentguard audit verify");
requireText("frontend/README.md", "AGENTGUARD_SESSION_STORE");
requireText("site/src/pages/docs/configuration.astro", "../../../../docs/configuration.md");
requireText("docs/configuration.md", "AGENTGUARD_SESSION_REDIS_URL");
requireText("docs/configuration.md", "AGENTGUARD_RATE_LIMIT_REDIS_URL");
requireText("docs/README.md", "[Configuration reference](configuration.md)");
requireText("site/src/pages/docs/reference.astro", "reference/generated/");
requireText("site/src/pages/docs/reference.astro", "PUBLIC_AGENTGUARD_REFERENCE");
requireText("scripts/stage-api-reference.mjs", "agentguard_server");
requireText(".github/workflows/deploy-site.yml", "Generate version-matched Rust API docs");
requireText(".github/workflows/deploy-site.yml", "Generate TypeScript declarations");
requireText(".github/workflows/deploy-site.yml", "Generate CLI and protobuf references");
requireText(".github/workflows/deploy-site.yml", "Stage generated API reference");
requireText("docs/production.md", "never becomes an implicit production fallback");
requireText("docs/production.md", "corrupted chained audit tail refuses startup");
requireText("docs/production.md", "regular file, not a symlink, FIFO, or device");
requireText("docs/production.md", "owner-only (`0600`) audit-file permissions");
requireText("docs/operations/runbook.md", "Do not increase PDP replicas");
requireText("docs/operations/runbook.md", "coordinated,\ndurable audit backend");
requireText("docs/operations/runbook.md", 'AGENTGUARD_GRPC_LISTEN="127.0.0.1:9443"');
requireText("frontend/src/components/theme_provider.tsx", "enableSystem");
requireText("frontend/src/components/theme_toggle.tsx", "aria-label");
requireText("frontend/src/app/globals.css", "prefers-reduced-motion");
requireText("README.md", "not standardized AuthZEN gRPC");
requireText("docs/architecture.md", "repository-defined gRPC mirror");
requireText("site/src/lib/content.ts", "repository-defined plaintext gRPC mirror");
requireText("RELEASE.md", "CI builds and scans the Docker images as test");
requireText("RELEASE.md", "does not publish container images to a registry");
requireText("RELEASE.md", "registry-reported image digests");
if (readFileSync(".github/workflows/ci.yml", "utf8").includes("docker push") &&
    !readFileSync("RELEASE.md", "utf8").includes("CI publishes the release images")) {
  failures.push("RELEASE.md: document registry publishing when CI starts publishing images");
}
if (readFileSync("RELEASE.md", "utf8").includes("digest produced by the container pipeline")) {
  failures.push("RELEASE.md: container CI does not publish registry digests");
}
if (readFileSync("deploy/k8s/pdp.yaml", "utf8").includes("AGENTGUARD_AUTH_KEY_FILE")) {
  failures.push("deploy/k8s/pdp.yaml: uses unsupported AGENTGUARD_AUTH_KEY_FILE environment contract");
}

for (const [file, stale] of [
  ["docs/kubernetes.md", "uses loopback and disabled authentication"],
  ["docs/operations/runbook.md", "Run multiple\nreplicas with a shared policy directory"],
  ["docs/operations/runbook.md", 'AGENTGUARD_GRPC_LISTEN="0.0.0.0:9443"'],
  ["site/src/pages/index.astro", "Workspace packages declare 0.2.0"],
  ["site/src/pages/docs/deploy.astro", "invalid clap requires"],
  ["site/src/pages/docs/configuration.astro", "invalid clap requires"],
  ["site/src/pages/docs/security.astro", "production-readiness claim"],
]) {
  if (readFileSync(file, "utf8").includes(stale)) failures.push(`${file}: stale public claim ${stale}`);
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log("public surface checks passed");
