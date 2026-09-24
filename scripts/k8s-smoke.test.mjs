import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const smokeScript = join(repoRoot, "scripts/k8s-smoke.sh");
const ciWorkflow = join(repoRoot, ".github/workflows/ci.yml");
const recordedCalls = (path) => existsSync(path) ? readFileSync(path, "utf8") : "";

test("CI bounds the Kubernetes smoke and captures failure diagnostics", () => {
  const workflow = readFileSync(ciWorkflow, "utf8");
  assert.match(
    workflow,
    /name: Kubernetes PDP smoke\s+timeout-minutes: 30[\s\S]*?name: Run Kubernetes startup, decision, audit, termination, and rollback smoke test[\s\S]*?run: timeout --foreground --signal=TERM --kill-after=20s 15m \.\/scripts\/k8s-smoke\.sh/,
  );
  assert.match(
    workflow,
    /name: Capture Kubernetes smoke diagnostics\s+if: failure\(\)[\s\S]*?kubectl -n agentguard get pods -o wide[\s\S]*?kubectl -n agentguard get events --sort-by=\.lastTimestamp/,
  );
});

function makeHarness({ context = "kind-agentguard-test", clusters = "agentguard-test" } = {}) {
  const directory = mkdtempSync(join(tmpdir(), "agentguard-k8s-guard-"));
  const bin = join(directory, "bin");
  const calls = join(directory, "kubectl-calls.log");
  const script = (name, source) => {
    const path = join(bin, name);
    writeFileSync(path, `#!/bin/sh\n${source}\n`);
    chmodSync(path, 0o700);
  };

  mkdirSync(bin);
  script("kubectl", `
if [ "$1" = config ] && [ "$2" = current-context ]; then
  printf '%s\\n' "$TEST_KUBE_CONTEXT"
  exit 0
fi
if [ "$1" = kustomize ]; then
  printf '%s\\n' \
    'image: registry.example.com/security/agentguard-server@sha256:REPLACE_WITH_64_HEX_PDP_DIGEST' \
    'image: registry.example.com/security/agentguard-console@sha256:REPLACE_WITH_64_HEX_CONSOLE_DIGEST' \
    'kind: PersistentVolumeClaim' \
    'name: agentguard-pdp' \
    'name: agentguard-console'
  exit 0
fi
printf '%s\\n' "$*" >> "$TEST_KUBECTL_CALLS"
exit 42`);
  script("kind", `
if [ "$1" = get ] && [ "$2" = clusters ]; then
  printf '%s\\n' "$TEST_KIND_CLUSTERS"
  exit 0
fi
exit 43`);
  for (const command of ["curl", "docker"]) script(command, "exit 0");

  return {
    directory,
    calls,
    run({ selected = "agentguard-test", confirmation, selectedContext = context, existing = clusters } = {}) {
      const env = {
        ...process.env,
        PATH: [bin, process.env.PATH].join(delimiter),
        TEST_KUBE_CONTEXT: selectedContext,
        TEST_KIND_CLUSTERS: existing,
        TEST_KUBECTL_CALLS: calls,
        AGENTGUARD_KIND_CLUSTER: selected,
      };
      if (confirmation === undefined) delete env.AGENTGUARD_K8S_CONFIRM_DISPOSABLE_CLUSTER;
      else env.AGENTGUARD_K8S_CONFIRM_DISPOSABLE_CLUSTER = confirmation;
      return spawnSync("bash", [smokeScript], { cwd: directory, env, encoding: "utf8" });
    },
    cleanup() {
      rmSync(directory, { recursive: true, force: true });
    },
  };
}

test("Kubernetes smoke refuses a mismatched context before any mutation", (t) => {
  const harness = makeHarness({ context: "production-admin@cluster" });
  t.after(() => harness.cleanup());
  const result = harness.run({ confirmation: "agentguard-test" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /refusing to mutate Kubernetes context/);
  assert.equal(recordedCalls(harness.calls), "");
});

test("Kubernetes smoke refuses a missing Kind cluster before any mutation", (t) => {
  const harness = makeHarness({ clusters: "other-cluster" });
  t.after(() => harness.cleanup());
  const result = harness.run({ confirmation: "agentguard-test" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Kind cluster 'agentguard-test' does not exist/);
  assert.equal(recordedCalls(harness.calls), "");
});

test("Kubernetes smoke requires exact explicit confirmation before any mutation", (t) => {
  const harness = makeHarness();
  t.after(() => harness.cleanup());
  const missing = harness.run();
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /set AGENTGUARD_K8S_CONFIRM_DISPOSABLE_CLUSTER=agentguard-test/);
  const mismatched = harness.run({ confirmation: "production" });
  assert.notEqual(mismatched.status, 0);
  assert.match(mismatched.stderr, /set AGENTGUARD_K8S_CONFIRM_DISPOSABLE_CLUSTER=agentguard-test/);
  assert.equal(recordedCalls(harness.calls), "");
});

test("Kubernetes smoke reaches its first mutation only for the confirmed disposable cluster", (t) => {
  const harness = makeHarness();
  t.after(() => harness.cleanup());
  const result = harness.run({ confirmation: "agentguard-test" });
  assert.notEqual(result.status, 0, "stub kubectl intentionally stops at the first mutation");
  const calls = recordedCalls(harness.calls);
  assert.match(calls, /create namespace agentguard /, `${result.stdout}\n${result.stderr}`);
  assert.doesNotMatch(calls, /apply -k|create secret/);
});
