import { cpSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const temporaryRoot = mkdtempSync(join(tmpdir(), "agentguard-kustomize-"));

try {
  const copiedDeploy = join(temporaryRoot, "deploy");
  cpSync(join(repoRoot, "deploy/k8s"), join(copiedDeploy, "k8s"), { recursive: true });
  const overlayDirectory = join(copiedDeploy, "overlays/production");
  mkdirSync(overlayDirectory, { recursive: true });
  copyFileSync(
    join(repoRoot, "deploy/overlays/production/kustomization.yaml.example"),
    join(overlayDirectory, "kustomization.yaml"),
  );

  const result = spawnSync("kubectl", ["kustomize", overlayDirectory], {
    encoding: "utf8",
    timeout: 30_000,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`kubectl kustomize failed:\n${result.stderr || result.stdout}`);
  }

  const rendered = result.stdout;
  const requirements = [
    "image: registry.example.com/security/agentguard-server@sha256:REPLACE_WITH_64_HEX_PDP_DIGEST",
    "image: registry.example.com/security/agentguard-console@sha256:REPLACE_WITH_64_HEX_CONSOLE_DIGEST",
    "kind: PersistentVolumeClaim",
    "name: agentguard-pdp",
    "name: agentguard-console",
  ];
  const missing = requirements.filter((value) => !rendered.includes(value));
  if (missing.length) {
    throw new Error(`rendered overlay is missing expected resources or image pins:\n${missing.join("\n")}`);
  }

  const template = readFileSync(
    join(repoRoot, "deploy/overlays/production/kustomization.yaml.example"),
    "utf8",
  );
  if (!template.includes("REPLACE_WITH_64_HEX_PDP_DIGEST") ||
      !template.includes("REPLACE_WITH_64_HEX_CONSOLE_DIGEST")) {
    throw new Error("production template must remain explicit about environment-specific digest input");
  }
  console.log("production Kustomize overlay rendered and pins both workload images");
} finally {
  rmSync(temporaryRoot, { recursive: true, force: true });
}
