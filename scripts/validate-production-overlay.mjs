import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const EXPECTED_IMAGES = ["agentguard-server", "agentguard-console"];
const IMAGE_REFERENCE = /^[a-zA-Z0-9._:-]+(?:\/[a-zA-Z0-9._-]+)+@sha256:[a-f0-9]{64}$/;

export function validateRenderedImages(rendered) {
  const images = [...rendered.matchAll(/^\s*image:\s*(\S+)\s*$/gm)]
    .map((match) => match[1]);
  const failures = [];

  for (const name of EXPECTED_IMAGES) {
    const matching = images.filter((image) =>
      image.includes(`/${name}@`) || image.startsWith(`${name}@`) ||
      image.includes(`/${name}:`) || image.startsWith(`${name}:`)
    );
    if (matching.length !== 1) {
      failures.push(`expected exactly one ${name} image, found ${matching.length}`);
      continue;
    }
    if (!IMAGE_REFERENCE.test(matching[0]) || matching[0].includes("registry.example.com")) {
      failures.push(`${name} must use a fully qualified registry image pinned by a 64-hex sha256 digest`);
    }
  }

  return failures;
}

export function validateOverlay(overlayDirectory) {
  const result = spawnSync("kubectl", ["kustomize", overlayDirectory], {
    encoding: "utf8",
    timeout: 30_000,
  });
  if (result.error) return [`could not run kubectl kustomize: ${result.error.message}`];
  if (result.status !== 0) {
    return [`kubectl kustomize failed: ${(result.stderr || result.stdout).trim()}`];
  }
  return validateRenderedImages(result.stdout);
}

function main() {
  const overlayDirectory = process.argv[2] || "deploy/overlays/production";
  const failures = validateOverlay(overlayDirectory);
  if (failures.length) {
    console.error(failures.join("\n"));
    process.exitCode = 1;
    return;
  }
  console.log(`production overlay validated: ${overlayDirectory}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
