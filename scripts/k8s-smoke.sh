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

cleanup() {
  if [[ -n "${port_forward_pid:-}" ]]; then
    kill "$port_forward_pid" 2>/dev/null || true
    wait "$port_forward_pid" 2>/dev/null || true
  fi
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
  --from-literal=20_agents.cedar='permit (principal is Agent, action, resource);' \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$namespace" scale deployment/agentguard-console --replicas=0
kubectl -n "$namespace" set image deployment/agentguard-pdp pdp="$image"
kubectl -n "$namespace" set env deployment/agentguard-pdp \
  AGENTGUARD_LISTEN=tcp://0.0.0.0:8443 \
  AGENTGUARD_AUTH=disabled \
  AGENTGUARD_ALLOW_LOOPBACK_BYPASS=1
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
  -d '{"subject":{"type":"Agent","id":"smoke"},"action":{"type":"Action","id":"ToolCall::repo_read"},"resource":{"type":"Repository","id":"demo"},"context":{"repo":"demo","session":{"ip":"127.0.0.1"}}}')
echo "$response" | grep -q '"decision":true'

denied=$(curl --silent --fail -X POST "http://127.0.0.1:$port/access/v1/evaluation" \
  -H 'content-type: application/json' \
  -d '{"subject":{"type":"User","id":"smoke"},"action":{"type":"Action","id":"ToolCall::repo_read"},"resource":{"type":"Repository","id":"demo"},"context":{"repo":"demo","session":{"ip":"127.0.0.1"}}}')
echo "$denied" | grep -q '"decision":false'

pod=$(kubectl -n "$namespace" get pods -l app=agentguard-pdp -o jsonpath='{.items[0].metadata.name}')
kubectl -n "$namespace" exec "$pod" -- test -s /var/lib/agentguard/audit/decisions.jsonl
kubectl -n "$namespace" exec "$pod" -- agentguard audit verify \
  --audit /var/lib/agentguard/audit/decisions.jsonl \
  --secret-file /etc/agentguard/secrets/chain-secret

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

echo "Kubernetes PDP smoke contract passed"
