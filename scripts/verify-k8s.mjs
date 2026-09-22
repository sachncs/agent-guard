import { existsSync, readFileSync } from "node:fs";

const root = "deploy/k8s";
const files = ["kustomization.yaml", "namespace.yaml", "configmap.yaml", "pdp.yaml", "console.yaml", "storage.yaml"];
const failures = [];
const read = (file) => readFileSync(`${root}/${file}`, "utf8");

for (const file of files) {
  if (!existsSync(`${root}/${file}`)) failures.push(`missing ${root}/${file}`);
}

if (failures.length === 0) {
  const kustomization = read("kustomization.yaml");
  for (const resource of files.slice(1)) {
    if (!kustomization.includes(`  - ${resource}`)) failures.push(`kustomization.yaml does not include ${resource}`);
  }

  const pdp = read("pdp.yaml");
  for (const value of [
    'value: "apikey:/etc/agentguard/keys/keys.json"',
    "path: /readyz",
    "path: /healthz",
    "startupProbe",
    "terminationGracePeriodSeconds: 30",
    "runAsNonRoot: true",
    "readOnlyRootFilesystem: true",
    "claimName: agentguard-audit",
  ]) if (!pdp.includes(value)) failures.push(`pdp.yaml missing ${value}`);

  const console = read("console.yaml");
  for (const value of [
    "secretRef: {name: agentguard-console-env}",
    "name: AGENTGUARD_BIN, value: /usr/local/bin/agentguard",
    "mountPath: /var/lib/agentguard/policies, readOnly: true",
    "mountPath: /var/lib/agentguard/audit, readOnly: true",
    "claimName: agentguard-audit",
    "podAffinity",
    "path: /login",
    "startupProbe",
    "terminationGracePeriodSeconds: 30",
    "runAsNonRoot: true",
    "readOnlyRootFilesystem: true",
  ]) if (!console.includes(value)) failures.push(`console.yaml missing ${value}`);
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log("Kubernetes manifest contract checks passed");
