import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";

const root = process.cwd();
const files = [
  "README.md",
  "BRAND.md",
  "CONTRIBUTING.md",
  "SECURITY.md",
  "SUPPORT.md",
  "RELEASE.md",
  ...readdirSync(resolve(root, "docs"), { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".md"))
    .map((entry) => `docs/${entry.name}`),
  ...readdirSync(resolve(root, "docs/operations"), { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".md"))
    .map((entry) => `docs/operations/${entry.name}`),
];

const failures = [];
const markdownLink = /!?(?:\[[^\]]*\])\(([^)\s]+)(?:\s+"[^"]*")?\)/g;

for (const relativeFile of files) {
  const file = resolve(root, relativeFile);
  const source = readFileSync(file, "utf8");
  for (const match of source.matchAll(markdownLink)) {
    const target = match[1].replace(/^<|>$/g, "");
    if (/^(?:https?:|mailto:|#)/.test(target)) continue;
    const path = target.split("#", 1)[0].split("?", 1)[0];
    if (!path) continue;
    const candidate = resolve(dirname(file), path);
    if (!existsSync(candidate)) {
      failures.push(`${relativeFile}: broken link ${target}`);
    }
  }
}

const requiredSiteRoutes = [
  "index.astro",
  "getting-started.astro",
  "concepts.astro",
  "deploy.astro",
  "production.astro",
  "kubernetes.astro",
  "console.astro",
  "api.astro",
  "identity.astro",
  "audit.astro",
  "configuration.astro",
  "operations.astro",
  "incident-response.astro",
  "security.astro",
  "compatibility.astro",
  "branding.astro",
];
for (const route of requiredSiteRoutes) {
  if (!existsSync(resolve(root, "site/src/pages/docs", route))) {
    failures.push(`site: missing canonical documentation route ${route}`);
  }
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log(`documentation links passed (${files.length} Markdown files)`);
