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
    'name: AGENTGUARD_AUDIT_MAX_BYTES, value: "67108864"',
    "path: /readyz",
    "path: /healthz",
    "startupProbe",
    "terminationGracePeriodSeconds: 30",
    "automountServiceAccountToken: false",
    "runAsNonRoot: true",
    "fsGroup: 10001",
    "fsGroupChangePolicy: OnRootMismatch",
    "readOnlyRootFilesystem: true",
    "claimName: agentguard-audit",
    "key: 20_agents.cedar, path: policies/20_agents.cedar",
  ]) if (!pdp.includes(value)) failures.push(`pdp.yaml missing ${value}`);

  const serverAuthzen = readFileSync("crates/agentguard-server/src/authzen.rs", "utf8");
  const auditReadinessTimeout = serverAuthzen.match(
    /const AUDIT_READINESS_TIMEOUT: Duration = Duration::from_secs\((\d+)\);/,
  );
  const kubernetesReadinessTimeout = pdp.match(
    /readinessProbe: \{httpGet: \{path: \/readyz, port: http\}, periodSeconds: \d+, timeoutSeconds: (\d+)/,
  );
  if (!auditReadinessTimeout) failures.push("server audit readiness timeout must be explicit");
  if (!kubernetesReadinessTimeout) failures.push("PDP readiness probe must set timeoutSeconds explicitly");
  if (
    auditReadinessTimeout &&
    kubernetesReadinessTimeout &&
    Number(kubernetesReadinessTimeout[1]) <= Number(auditReadinessTimeout[1])
  ) {
    failures.push("PDP readiness probe timeout must exceed the bounded audit readiness timeout");
  }

  const configmap = read("configmap.yaml");
  for (const value of ["schema.cedarschema:", "entity User;", "entity Agent", "20_agents.cedar:"]) {
    if (!configmap.includes(value)) failures.push(`configmap.yaml missing ${value}`);
  }

  const smoke = readFileSync("scripts/k8s-smoke.sh", "utf8");
  if (!smoke.includes("AGENTGUARD_PDP_BEARER=unused-smoke")) {
    failures.push("k8s-smoke.sh must satisfy the console PDP credential Secret reference");
  }
  if (!smoke.includes('--user "$(id -u):$(id -g)"')) {
    failures.push("k8s-smoke.sh must run key-store writes as the host uid/gid for kubectl access");
  }
  if (smoke.includes('chmod 0777 "$key_dir"')) {
    failures.push("k8s-smoke.sh must keep its temporary key directory private");
  }
  if (!smoke.includes('"session":{"ip":"127.0.0.1"}')) {
    failures.push("k8s-smoke.sh must provide the required session record");
  }
  for (const value of [
    "api-key create",
    'AGENTGUARD_AUTH=disabled',
    'printf \'header = "authorization: Bearer %s"\\n\' "$raw_key" | curl --config -',
    'api-key revoke',
    '[[ "$status" == 401 ]]',
    "audit_records_before_upgrade=",
    "audit_records_after_recovery=",
    'agentguard audit verify',
    "audit record count changed across upgrade/rollback/pod replacement",
  ]) {
    const present = smoke.includes(value);
    if (value === 'AGENTGUARD_AUTH=disabled' ? present : !present) {
      failures.push(`k8s-smoke.sh must verify production key auth and live revocation (${value})`);
    }
  }
  if (
    !smoke.includes('printf \'%s\' "$key_json" | node -e') ||
    !smoke.includes('readFileSync(0, "utf8")') ||
    !smoke.includes("unset raw_key key_json")
  ) {
    failures.push("k8s-smoke.sh must parse and clear one-time key material through stdin");
  }
  if (smoke.includes('-H "authorization: Bearer $raw_key"')) {
    failures.push("k8s-smoke.sh must not expose the raw API key in curl process arguments");
  }
  if (/JSON\.parse\(process\.argv\[1\]\).*key_json/.test(smoke)) {
    failures.push("k8s-smoke.sh must not pass the API-key JSON as a process argument");
  }
  const revocationSmoke = smoke.slice(smoke.indexOf("api-key revoke"));
  if (!revocationSmoke.includes("seq 1 120")) {
    failures.push("k8s-smoke.sh must allow for eventual Kubernetes Secret projection during revocation");
  }

  const operationsGuide = readFileSync("docs/kubernetes.md", "utf8");
  const productionGuide = readFileSync("docs/production.md", "utf8");
  for (const value of [
    "production overlay is intentionally not checked in",
    "Before using the",
    "create that",
    "[Kubernetes deployment guide](kubernetes.md#deploy)",
  ]) if (!productionGuide.includes(value)) {
    failures.push(`docs/production.md must explain the operator-owned overlay prerequisite: ${value}`);
  }
  for (const value of [
    "deploy/k8s/overlays/production/kustomization.yaml",
    "registry-reported",
    "digest: sha256:<PDP_DIGEST>",
    "digest: sha256:<CONSOLE_DIGEST>",
    "kubectl apply -k deploy/k8s/overlays/production",
  ]) if (!operationsGuide.includes(value)) {
    failures.push(`docs/kubernetes.md must document production digest pinning: ${value}`);
  }
  for (const value of [
    "AGENTGUARD_TRUST_PROXY_HEADERS='1'",
    "AGENTGUARD_PDP_ALLOW_INSECURE_INTERNAL='1'",
    "must remove incoming `X-Forwarded-For`, `X-Forwarded-Host`, and",
  ]) if (!operationsGuide.includes(value)) {
    failures.push(`docs/kubernetes.md missing trusted-proxy requirement: ${value}`);
  }
  if (!/exactly\s+one validated client address/.test(operationsGuide)) {
    failures.push("docs/kubernetes.md must require one validated forwarded client address");
  }
  for (const value of [
    "console currently calls the PDP Service over plain HTTP",
    "TLS at the external ingress does not encrypt this internal connection",
    "service mesh that enforces mTLS",
    "NetworkPolicy limits reachability but does not encrypt traffic",
    "identity-provider, Redis, and DNS peers are environment-specific",
  ]) if (!operationsGuide.toLowerCase().replaceAll(/\s+/g, " ").includes(value.toLowerCase())) {
    failures.push(`docs/kubernetes.md must describe the in-cluster network trust boundary: ${value}`);
  }

  const console = read("console.yaml");
  for (const value of [
    "secretRef: {name: agentguard-console-env}",
    "key: AGENTGUARD_PDP_BEARER",
    "name: AGENTGUARD_BIN, value: /usr/local/bin/agentguard",
    'name: AGENTGUARD_PDP_ALLOW_INSECURE_INTERNAL, value: "1"',
    "name: AGENTGUARD_DELEGATION_KEY_FILE, value: /etc/agentguard/delegation/delegation.key",
    "mountPath: /var/lib/agentguard/policies, readOnly: true",
    "mountPath: /var/lib/agentguard/audit, readOnly: true",
    "mountPath: /etc/agentguard/delegation, readOnly: true",
    "claimName: agentguard-audit",
    "secretName: agentguard-delegation-key",
    "key: 20_agents.cedar, path: policies/20_agents.cedar",
    "podAffinity",
    "path: /api/health/ready",
    "path: /api/health/live",
    "startupProbe",
    "terminationGracePeriodSeconds: 30",
    "automountServiceAccountToken: false",
    "runAsNonRoot: true",
    "fsGroup: 10001",
    "fsGroupChangePolicy: OnRootMismatch",
    "readOnlyRootFilesystem: true",
  ]) if (!console.includes(value)) failures.push(`console.yaml missing ${value}`);
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log("Kubernetes manifest contract checks passed");
