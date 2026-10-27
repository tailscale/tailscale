#!/usr/bin/env bash
set -euo pipefail
TEST=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(git -C "$TEST" rev-parse --show-toplevel)
WORK=$(mktemp -d)
OUT="${RESULTS_DIR:-$(mktemp -d)}"
CLUSTER=tailscale-dns-resolution-test
GO="${GO:-$ROOT/tool/go}"
mkdir -p "$WORK/image" "$WORK/tools" "$OUT"
export KUBECONFIG="$WORK/kubeconfig"
KIND="${KIND:-$WORK/tools/kind}"
cd "$ROOT"
OWN_CLUSTER=0
cleanup() {
  if [[ "$OWN_CLUSTER" == 1 ]]; then "$KIND" delete cluster --name "$CLUSTER"; fi
  rm -rf "$WORK"
  echo "DNS diagnostic test artifacts: $OUT"
}
trap cleanup EXIT
if [[ ! -x "$KIND" ]]; then GOBIN="$WORK/tools" "$GO" install sigs.k8s.io/kind; fi
if "$KIND" get clusters | grep -qx "$CLUSTER"; then
  echo "Refusing to reuse existing cluster $CLUSTER." >&2
  exit 1
fi
OWN_CLUSTER=1
"$KIND" create cluster --name "$CLUSTER" --image kindest/node:v1.35.0 --kubeconfig "$KUBECONFIG" --wait 120s
K=(kubectl --kubeconfig "$KUBECONFIG" --context "kind-$CLUSTER")
ARCH=$("${K[@]}" get node "$CLUSTER-control-plane" -o jsonpath='{.status.nodeInfo.architecture}')
GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 "$GO" build -o "$WORK/image/controller" ./k8s-operator/reconciler/nameserver/testdata/dnsconfig-resolution/_controller
GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 "$GO" build -o "$WORK/image/k8s-nameserver" ./cmd/k8s-nameserver
cp "$TEST/Dockerfile" "$WORK/image/Dockerfile"
docker build -t tailscale-dns-implementation:local "$WORK/image"
"$KIND" load docker-image --name "$CLUSTER" tailscale-dns-implementation:local
"${K[@]}" apply -f cmd/k8s-operator/deploy/crds/tailscale.com_dnsconfigs.yaml
"${K[@]}" wait --for=condition=Established crd/dnsconfigs.tailscale.com --timeout=60s
"${K[@]}" apply -f "$TEST/fixtures.yaml"
"${K[@]}" wait --for=condition=NameserverReady dnsconfig/implementation --timeout=120s
"${K[@]}" get dnsconfig implementation -o json > "$OUT/empty.json"
"${K[@]}" -n tailscale patch configmap dnsrecords --type merge -p '{"data":{"records.json":"{\"version\":\"v1alpha1\",\"ip4\":{\"reports.reproduction.ts.net\":[\"192.0.2.42\"]},\"ip6\":{\"reports.reproduction.ts.net\":[\"2001:db8::42\"]}}"}}'
# The requested image does not exist. A provisioned Service without a running
# nameserver cannot establish a forwarding mismatch and must stay Unknown.
"${K[@]}" wait --for=jsonpath='{.status.conditions[?(@.type=="DNSResolutionReady")].reason}'=NameserverUnavailable dnsconfig/implementation --timeout=120s
"${K[@]}" get dnsconfig implementation -o json > "$OUT/unavailable.json"
# Exceed the two-minute grace without a direct answer.
sleep 50
sleep 50
sleep 35
"${K[@]}" get dnsconfig implementation -o json > "$OUT/unavailable-again.json"
"${K[@]}" -n tailscale get pods -o json > "$OUT/pods-unavailable.json"
"${K[@]}" get events --all-namespaces --field-selector involvedObject.name=implementation -o json > "$OUT/events-unavailable.json"
"${K[@]}" patch dnsconfig implementation --type merge -p '{"spec":{"nameserver":{"image":{"tag":"local"}}}}'
"${K[@]}" wait --for=condition=DNSResolutionReady=False dnsconfig/implementation --timeout=240s
"${K[@]}" get dnsconfig implementation -o json > "$OUT/failed.json"
"${K[@]}" -n tailscale get pods -o json > "$OUT/pods-before.json"
# Observe at least one more scheduled check; identical failures must stay quiet.
sleep 35
"${K[@]}" get dnsconfig implementation -o json > "$OUT/failed-again.json"
"${K[@]}" get events --all-namespaces --field-selector involvedObject.name=implementation -o json > "$OUT/events-failed.json"
NS_IP=$("${K[@]}" get dnsconfig implementation -o jsonpath='{.status.nameserver.ip}')
"${K[@]}" -n kube-system get configmap coredns -o json > "$OUT/coredns-before.json"
python3 - "$OUT" "$NS_IP" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]); core=json.loads((p/'coredns-before.json').read_text())['data']['Corefile']
assert 'ts.net:53' not in core
core+='\nts.net:53 {\n    errors\n    cache 5\n    forward . '+sys.argv[2]+'\n}\n'
(p/'forwarding-patch.json').write_text(json.dumps({'data':{'Corefile':core}}))
PY
"${K[@]}" -n kube-system patch configmap coredns --type merge --patch-file "$OUT/forwarding-patch.json"
"${K[@]}" wait --for=condition=DNSResolutionReady dnsconfig/implementation --timeout=240s
"${K[@]}" get dnsconfig implementation -o json > "$OUT/recovered.json"
sleep 35
"${K[@]}" get dnsconfig implementation -o json > "$OUT/recovered-again.json"
"${K[@]}" get events --all-namespaces --field-selector involvedObject.name=implementation -o json > "$OUT/events-recovered.json"
"${K[@]}" -n tailscale get pods -o json > "$OUT/pods-after.json"
"${K[@]}" -n tailscale logs deployment/dnsconfig-controller --tail=150 > "$OUT/controller.log"
python3 "$TEST/verify.py" "$OUT"
