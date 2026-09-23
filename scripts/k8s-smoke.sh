#!/usr/bin/env bash
set -euo pipefail

# Run the PDP smoke contract against a disposable kind cluster. This script
# deliberately uses disabled auth only inside the isolated test
# namespace; production manifests keep API-key auth enabled.

# The checked-in Kustomize base intentionally fixes the namespace to
# `agentguard`; use a disposable cluster for this script rather than trying to
# override that production reference namespace.
namespace=${AGENTGUARD_K8S_NAMESPACE:-agentguard}
image=${AGENTGUARD_K8S_IMAGE:-agentguard-server:smoke}
rollback_image=${AGENTGUARD_K8S_ROLLBACK_IMAGE:-agentguard-server:smoke-rollback}
port=${AGENTGUARD_K8S_PORT:-18443}
kind_cluster=${AGENTGUARD_KIND_CLUSTER:-kind}

command -v kubectl >/dev/null || { echo "kubectl is required" >&2; exit 1; }
command -v kind >/dev/null || { echo "kind is required" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
command -v node >/dev/null || { echo "node is required" >&2; exit 1; }

key_dir=$(mktemp -d "$PWD/.k8s-smoke.XXXXXX")
key_store="$key_dir/keys.json"

cleanup() {
  if [[ -n "${port_forward_pid:-}" ]]; then
    kill "$port_forward_pid" 2>/dev/null || true
    wait "$port_forward_pid" 2>/dev/null || true
  fi
  rm -rf "$key_dir"
}
trap cleanup EXIT

kubectl create namespace "$namespace" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$namespace" create secret generic agentguard-secrets \
  --from-literal=chain-secret=smoke-chain-secret \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$namespace" create secret generic agentguard-api-keys \
  --from-literal=keys.json='[]' \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$namespace" create secret generic agentguard-console-env \
  --from-literal=AGENTGUARD_OIDC_ISSUER=http://127.0.0.1:9 \
  --from-literal=AGENTGUARD_OIDC_CLIENT_ID=smoke \
  --from-literal=AGENTGUARD_OIDC_CLIENT_SECRET=smoke \
  --from-literal=AGENTGUARD_SESSION_SECRET=smoke-session-secret-which-is-long-enough \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$namespace" create secret generic agentguard-delegation-key \
  --from-literal=delegation.key=smoke-delegation-key \
  --dry-run=client -o yaml | kubectl apply -f -

# The PDP is the only workload under test. Avoid pulling the console image
# while retaining the same namespace resources as the reference package.
kubectl -n "$namespace" apply -k deploy/k8s
kubectl -n "$namespace" create configmap agentguard-policies \
  --from-file=schema.cedarschema=schemas/starter.cedarschema \
  --from-literal=20_agents.cedar='permit (principal is Agent, action == Action::"ToolCall::repo_read", resource);' \
  --dry-run=client -o yaml | kubectl apply -f -

# Start the production-authenticated workload with a real identity-bound key.
# Generate the credential using the release CLI in the same image that will
# run in Kubernetes, then mount its persisted hash as a Secret.
key_json=$(docker run --rm --user "$(id -u):$(id -g)" \
  --volume "$key_dir:/keys" \
  --entrypoint /usr/local/bin/agentguard "$image" \
  --output json api-key create \
  --key-store /keys/keys.json \
  --subject-type Agent --subject-id smoke --scope authorize)
key_id=$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).id)' "$key_json")
raw_key=$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).raw_secret)' "$key_json")
kubectl -n "$namespace" create secret generic agentguard-api-keys \
  --from-file=keys.json="$key_store" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n "$namespace" scale deployment/agentguard-console --replicas=0
kubectl -n "$namespace" set image deployment/agentguard-pdp pdp="$image"
kubectl -n "$namespace" set env deployment/agentguard-pdp \
  AGENTGUARD_LISTEN=tcp://0.0.0.0:8443
kubectl -n "$namespace" rollout restart deployment/agentguard-pdp
kubectl -n "$namespace" rollout status deployment/agentguard-pdp --timeout=180s

pod=$(kubectl -n "$namespace" get pods -l app=agentguard-pdp -o jsonpath='{.items[0].metadata.name}')
kubectl -n "$namespace" port-forward "pod/$pod" "$port:8443" >/tmp/agentguard-k8s-port-forward.log 2>&1 &
port_forward_pid=$!
for _ in $(seq 1 30); do
  if curl --silent --fail "http://127.0.0.1:$port/healthz" >/dev/null; then break; fi
  sleep 2
done
curl --silent --fail "http://127.0.0.1:$port/healthz" >/dev/null
curl --silent --fail "http://127.0.0.1:$port/readyz" >/dev/null

response=$(curl --silent --fail -X POST "http://127.0.0.1:$port/access/v1/evaluation" \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $raw_key" \
  -d '{"subject":{"type":"Agent","id":"smoke"},"action":{"type":"Action","id":"ToolCall::repo_read"},"resource":{"type":"Repository","id":"demo"},"context":{"repo":"demo","session":{"ip":"127.0.0.1"}}}')
echo "$response" | grep -q '"decision":true'

denied=$(curl --silent --fail -X POST "http://127.0.0.1:$port/access/v1/evaluation" \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $raw_key" \
  -d '{"subject":{"type":"Agent","id":"smoke"},"action":{"type":"Action","id":"ToolCall::shell_exec"},"resource":{"type":"Repository","id":"demo"},"context":{"cmd":"echo smoke","session":{"ip":"127.0.0.1"}}}')
echo "$denied" | grep -q '"decision":false'

# Revoke the key in the source store and update the mounted Secret. The
# running PDP must observe the Kubernetes projected-volume update without a
# rollout, then reject the same credential at the HTTP authentication layer.
docker run --rm --user "$(id -u):$(id -g)" \
  --volume "$key_dir:/keys" \
  --entrypoint /usr/local/bin/agentguard "$image" \
  api-key revoke --key-store /keys/keys.json "$key_id"
kubectl -n "$namespace" create secret generic agentguard-api-keys \
  --from-file=keys.json="$key_store" \
  --dry-run=client -o yaml | kubectl apply -f -
# Kubelet Secret projection is eventually consistent and its sync/cache period
# can be much longer than the PDP's 250 ms content poll interval.
for _ in $(seq 1 120); do
  status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
    -X POST "http://127.0.0.1:$port/access/v1/evaluation" \
    -H 'content-type: application/json' \
    -H "authorization: Bearer $raw_key" \
    -d '{"subject":{"type":"Agent","id":"smoke"},"action":{"type":"Action","id":"ToolCall::repo_read"},"resource":{"type":"Repository","id":"demo"},"context":{"repo":"demo","session":{"ip":"127.0.0.1"}}}')
  if [[ "$status" == 401 ]]; then break; fi
  sleep 1
done
[[ "$status" == 401 ]] || {
  echo "revoked API key still accepted (HTTP $status)" >&2
  exit 1
}

pod=$(kubectl -n "$namespace" get pods -l app=agentguard-pdp -o jsonpath='{.items[0].metadata.name}')
kubectl -n "$namespace" exec "$pod" -- test -s /var/lib/agentguard/audit/decisions.jsonl
kubectl -n "$namespace" exec "$pod" -- agentguard audit verify \
  --audit /var/lib/agentguard/audit/decisions.jsonl \
  --secret-file /etc/agentguard/secrets/chain-secret
audit_records_before_upgrade=$(kubectl -n "$namespace" exec "$pod" -- \
  wc -l /var/lib/agentguard/audit/decisions.jsonl | tr -d '[:space:]')

# Exercise graceful replacement and a real rollback operation using the same
# verified image under a new immutable tag.
kind load docker-image --name "$kind_cluster" "$rollback_image"
kubectl -n "$namespace" set image deployment/agentguard-pdp pdp="$rollback_image"
kubectl -n "$namespace" rollout status deployment/agentguard-pdp --timeout=180s
kubectl -n "$namespace" rollout undo deployment/agentguard-pdp
kubectl -n "$namespace" rollout status deployment/agentguard-pdp --timeout=180s
pod=$(kubectl -n "$namespace" get pods -l app=agentguard-pdp -o jsonpath='{.items[0].metadata.name}')
kubectl -n "$namespace" delete pod "$pod" --wait=false
kubectl -n "$namespace" rollout status deployment/agentguard-pdp --timeout=180s
pod=$(kubectl -n "$namespace" get pods -l app=agentguard-pdp -o jsonpath='{.items[0].metadata.name}')
audit_records_after_recovery=$(kubectl -n "$namespace" exec "$pod" -- \
  wc -l /var/lib/agentguard/audit/decisions.jsonl | tr -d '[:space:]')
[[ "$audit_records_after_recovery" == "$audit_records_before_upgrade" ]] || {
  echo "audit record count changed across upgrade/rollback/pod replacement " \
    "($audit_records_before_upgrade -> $audit_records_after_recovery)" >&2
  exit 1
}
kubectl -n "$namespace" exec "$pod" -- agentguard audit verify \
  --audit /var/lib/agentguard/audit/decisions.jsonl \
  --secret-file /etc/agentguard/secrets/chain-secret

echo "Kubernetes PDP smoke contract passed"
