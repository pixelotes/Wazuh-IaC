#!/usr/bin/env bash
# Local bootstrap: kind cluster -> Argo CD -> root app (everything else is GitOps).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CTX=kind-wazuh

kind get clusters | grep -qx wazuh || kind create cluster --config "$ROOT/kind/cluster.yaml"

helm repo add argo https://argoproj.github.io/argo-helm >/dev/null
helm upgrade --install argocd argo/argo-cd --version 10.11.6 \
  --kube-context "$CTX" -n argocd --create-namespace \
  -f "$ROOT/bootstrap/argocd-values.yaml" --wait

"$ROOT/scripts/gen-secrets.sh"

echo "Commit values/wazuh-credentials.yaml, serve the repo (scripts/serve-repo.sh), then:"
echo "  kubectl --context $CTX apply -f bootstrap/root-app.yaml"
