#!/usr/bin/env bash
# Install kind + kubectl into integrations/ai-assistant/.bin (no root).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/.bin"
mkdir -p "$BIN"
KIND_VERSION="${KIND_VERSION:-v0.27.0}"
KUBECTL_VERSION="${KUBECTL_VERSION:-v1.31.0}"

if [[ ! -x "$BIN/kind" ]]; then
  echo "downloading kind ${KIND_VERSION}..."
  curl -fsSL "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-amd64" -o "$BIN/kind"
  chmod +x "$BIN/kind"
fi
if [[ ! -x "$BIN/kubectl" ]]; then
  echo "downloading kubectl ${KUBECTL_VERSION}..."
  curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" -o "$BIN/kubectl"
  chmod +x "$BIN/kubectl"
fi
echo "kind: $($BIN/kind version)"
echo "kubectl: $($BIN/kubectl version --client -short 2>/dev/null || $BIN/kubectl version --client)"
