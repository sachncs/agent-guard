import { readFileSync } from "node:fs";
import { isValidReleaseTag } from "./validate-release-tag.mjs";

const rootPackage = JSON.parse(readFileSync("package.json", "utf8"));
const sitePackage = JSON.parse(readFileSync("site/package.json", "utf8"));
const siteWorkspace = readFileSync("site/pnpm-workspace.yaml", "utf8");
const setup = readFileSync("scripts/setup.sh", "utf8");
const nodeVersionCheck = readFileSync("scripts/check-node-version.mjs", "utf8");
const ci = readFileSync(".github/workflows/ci.yml", "utf8");
const release = readFileSync(".github/workflows/release.yml", "utf8");
const consoleDockerfile = readFileSync("frontend/Dockerfile", "utf8");
const failures = [];

if (rootPackage.packageManager !== "pnpm@11.22.0") {
  failures.push("root workspace must pin pnpm@11.22.0");
}
if (sitePackage.packageManager !== rootPackage.packageManager) {
  failures.push("site and root workspaces must use the same pinned pnpm");
}
if (rootPackage.engines?.node !== ">=22.12" || sitePackage.engines?.node !== ">=22.12") {
  failures.push("the full repository and Astro site must declare the Astro 7 Node.js minimum");
}

const allowBuilds = siteWorkspace.match(/^allowBuilds:\s*\n((?:^[ \t]+[^\n]*\n?)+)/m)?.[1] ?? "";
const approvedBuilds = [...allowBuilds.matchAll(/^\s+([^:\s]+):\s*(true|false)\s*$/gm)]
  .map(([, name, allowed]) => [name, allowed]);
const expectedBuilds = new Map([
  ["esbuild", "true"],
  ["sharp", "true"],
]);
if (!release.includes('node scripts/validate-release-tag.mjs "$tag"')) {
  failures.push("release workflow must use the tested semantic-version tag validator");
}

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
if (
  !setup.includes("node scripts/check-node-version.mjs") ||
  !nodeVersionCheck.includes("MINIMUM_NODE = { major: 22, minor: 12 }")
) {
  failures.push("bootstrap must reject Node.js versions older than the declared 22.12 minimum");
}
if (!ci.includes("node --test scripts/*.test.mjs")) {
  failures.push("CI must run the repository tooling test suites");
}
if (
  !consoleDockerfile.includes("ARG AGENTGUARD_CLI_IMAGE") ||
  !consoleDockerfile.includes("COPY --from=cli-source") ||
  /cargo build/.test(consoleDockerfile)
) {
  failures.push("console image must reuse the CLI from an explicit PDP image, not rebuild it");
}
if (
  !ci.includes("AGENTGUARD_CLI_IMAGE=agentguard-server:ci") ||
  !ci.includes("--entrypoint /usr/local/bin/agentguard agentguard-console:ci --help")
) {
  failures.push("container CI must provide and verify the console image's shared CLI");
}

const checkoutCount = [...ci.matchAll(/uses: actions\/checkout@v5/g)].length;
const refCount = [...ci.matchAll(/ref: \$\{\{ inputs\.checkout_ref \|\| github\.sha \}\}/g)].length;
if (checkoutCount !== refCount || !ci.includes("checkout_ref:")) {
  failures.push("every reusable CI checkout must honor its explicit tested ref");
}
if (
  release.indexOf("resolve-tag:") < 0 ||
  release.indexOf("resolve-tag:") > release.indexOf("release-gate:") ||
  !release.includes("checkout_ref: ${{ needs.resolve-tag.outputs.tag }}") ||
  !release.includes("ref: ${{ needs.resolve-tag.outputs.tag }}") ||
  !release.includes('gh release create "$RELEASE_TAG"') ||
  !release.includes('git rev-parse --verify --quiet "refs/tags/${tag}^{commit}"')
) {
  failures.push("release gate, tested checkout, and publication must use the same existing tag");
}

for (const tag of ["v0.3.0", "v1.2.3-rc.1", "v2.0.0+build.7", "v1.2.3-0A", "v1.2.3-alpha+build.01"]) {
  if (!isValidReleaseTag(tag)) failures.push(`release tag validator rejected valid tag ${tag}`);
}
for (const tag of ["0.3.0", "v01.2.3", "v1.2", "v1x.2.3", "v1.2.3-01", "v1.2.3-", "v1.2.3+", "v1.2.3+build..7"]) {
  if (isValidReleaseTag(tag)) failures.push(`release tag validator accepted invalid tag ${tag}`);
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log("workspace toolchain and install-script contract passed");
