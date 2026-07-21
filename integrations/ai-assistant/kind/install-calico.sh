#!/usr/bin/env bash
# Install Calico on kind (kindnetd is disabled in cluster.yaml — required for
# NetworkPolicy enforcement in Track B).
set -euo pipefail
CALICO_VERSION="${CALICO_VERSION:-v3.28.2}"
POD_CIDR="${KIND_POD_CIDR:-10.244.0.0/16}"
echo "installing Calico ${CALICO_VERSION} (pod CIDR ${POD_CIDR})..."
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
curl -fsSL "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml" -o "$TMP"
# kind defaults to 10.244.0.0/16 when disableDefaultCNI is set.
sed -i \
  -e 's|# - name: CALICO_IPV4POOL_CIDR|- name: CALICO_IPV4POOL_CIDR|' \
  -e 's|#   value: "192.168.0.0/16"|  value: "'"${POD_CIDR}"'"|' \
  -e '/- name: FELIX_HEALTHENABLED/a\            - name: FELIX_IGNORELOOSERPF\n              value: "true"' \
  "$TMP"
kubectl apply -f "$TMP"
echo "waiting for Calico pods..."
for _ in $(seq 1 60); do
  if kubectl get pods -n kube-system -l k8s-app=calico-node --no-headers 2>/dev/null | grep -q .; then
    break
  fi
  sleep 2
done
kubectl wait --namespace kube-system --for=condition=ready pod -l k8s-app=calico-node --timeout=300s
kubectl wait --for=condition=Ready node --all --timeout=300s
echo "Calico ready"
