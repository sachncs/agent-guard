import { existsSync, readFileSync } from "node:fs";

const files = ["README.md", "CONTRIBUTING.md", "SUPPORT.md", "SECURITY.md", "BRAND.md", "frontend/README.md"];
const forbidden = ["agentguard_console", "agentguard_ console"];
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
}

for (const file of [
  "site/public/agentguard-mark-dark.svg",
  "site/public/agentguard-mark-mono.svg",
  "site/public/agentguard-wordmark.svg",
  "site/public/favicon.svg",
  "site/public/og-image.svg",
  "docs/production.md",
  "scripts/k8s-smoke.sh",
  "deploy/k8s/kustomization.yaml",
]) requireFile(file);

requireText("deploy/k8s/pdp.yaml", 'name: AGENTGUARD_AUTH, value: "apikey:/etc/agentguard/keys/keys.json"');
requireText("frontend/Dockerfile", "RUN cargo build --locked --release -p agentguard-cli");
requireText("frontend/Dockerfile", "ENV AGENTGUARD_BIN=/usr/local/bin/agentguard");
if (readFileSync("deploy/k8s/pdp.yaml", "utf8").includes("AGENTGUARD_AUTH_KEY_FILE")) {
  failures.push("deploy/k8s/pdp.yaml: uses unsupported AGENTGUARD_AUTH_KEY_FILE environment contract");
}

for (const [file, stale] of [
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
