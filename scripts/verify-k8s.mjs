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
    "automountServiceAccountToken: false",
    "runAsNonRoot: true",
    "readOnlyRootFilesystem: true",
    "claimName: agentguard-audit",
    "key: 20_agents.cedar, path: policies/20_agents.cedar",
  ]) if (!pdp.includes(value)) failures.push(`pdp.yaml missing ${value}`);

  const configmap = read("configmap.yaml");
  for (const value of ["schema.cedarschema:", "entity User;", "entity Agent", "20_agents.cedar:"]) {
    if (!configmap.includes(value)) failures.push(`configmap.yaml missing ${value}`);
  }

  const smoke = readFileSync("scripts/k8s-smoke.sh", "utf8");
  if (!smoke.includes('"session":{"ip":"127.0.0.1"}')) {
    failures.push("k8s-smoke.sh must provide the required session record");
  }

  const console = read("console.yaml");
  for (const value of [
    "secretRef: {name: agentguard-console-env}",
    "name: AGENTGUARD_BIN, value: /usr/local/bin/agentguard",
    "name: AGENTGUARD_DELEGATION_KEY_FILE, value: /etc/agentguard/delegation/delegation.key",
    "mountPath: /var/lib/agentguard/policies, readOnly: true",
    "mountPath: /var/lib/agentguard/audit, readOnly: true",
    "mountPath: /etc/agentguard/delegation, readOnly: true",
    "claimName: agentguard-audit",
    "secretName: agentguard-delegation-key",
    "key: 20_agents.cedar, path: policies/20_agents.cedar",
    "podAffinity",
    "path: /login",
    "startupProbe",
    "terminationGracePeriodSeconds: 30",
    "automountServiceAccountToken: false",
    "runAsNonRoot: true",
    "readOnlyRootFilesystem: true",
  ]) if (!console.includes(value)) failures.push(`console.yaml missing ${value}`);
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log("Kubernetes manifest contract checks passed");
