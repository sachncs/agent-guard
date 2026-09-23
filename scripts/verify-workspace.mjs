import { readFileSync } from "node:fs";

const rootPackage = JSON.parse(readFileSync("package.json", "utf8"));
const sitePackage = JSON.parse(readFileSync("site/package.json", "utf8"));
const siteWorkspace = readFileSync("site/pnpm-workspace.yaml", "utf8");
const setup = readFileSync("scripts/setup.sh", "utf8");
const ci = readFileSync(".github/workflows/ci.yml", "utf8");
const failures = [];

if (rootPackage.packageManager !== "pnpm@11.22.0") {
  failures.push("root workspace must pin pnpm@11.22.0");
}
if (sitePackage.packageManager !== rootPackage.packageManager) {
  failures.push("site and root workspaces must use the same pinned pnpm");
}

const allowBuilds = siteWorkspace.match(/^allowBuilds:\s*\n((?:^[ \t]+[^\n]*\n?)+)/m)?.[1] ?? "";
const approvedBuilds = [...allowBuilds.matchAll(/^\s+([^:\s]+):\s*(true|false)\s*$/gm)]
  .map(([, name, allowed]) => [name, allowed]);
const expectedBuilds = new Map([
  ["esbuild", "true"],
  ["sharp", "true"],
]);
if (
  approvedBuilds.length !== expectedBuilds.size ||
  approvedBuilds.some(([name, allowed]) => expectedBuilds.get(name) !== allowed)
) {
  failures.push("site install scripts must explicitly allow only esbuild and sharp");
}
if (/dangerouslyAllowAllBuilds/.test(setup) || /dangerouslyAllowAllBuilds/.test(ci)) {
  failures.push("bootstrap and CI must not enable dependency build scripts globally");
}
if (!setup.includes("npm exec --yes --package=pnpm@11.22.0 -- pnpm")) {
  failures.push("bootstrap must support pinned pnpm when Corepack is unavailable");
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log("workspace toolchain and install-script contract passed");
