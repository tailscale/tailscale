#!/usr/bin/env bash

set -eu

# This script builds the latest operator and proxy images and manifests and
# installs them as well as ingress-nginx chart to the current kube cluster. Run
# it with KIND=<cluster-name> to upload images to a kind cluster else you must
# pass REPO env var pointing at a public repository where the images will be
# pushed.
# This script is also run from ./scripts/kubetests/test_on_kind.sh
# Run it with:
# OAUTH_CLIENT_ID=<oauth client ID> \
# OAUTH_CLIENT_SECRET=<oauth-client-secret> \
# [REPO=<image registry>] \
# [KIND=<kind-cluster-name>] \
# ./scripts/kubetests/setup.sh

OAUTH_CLIENT_ID="$OAUTH_CLIENT_ID"
OAUTH_CLIENT_SECRET="$OAUTH_CLIENT_SECRET"
KIND=${KIND:-}

if [[ ! -z "$KIND" ]]; then
  REPO="tailscale-for-kind"
fi

REPO="$REPO"

eval `./tool/go run ./cmd/mkversion`

args=(TAGS="${VERSION_SHORT}")

make kube-generate-all # ensure things are up to date

if [[ ! -z "$KIND" ]]; then
args+=" PLATFORM=local"
fi

make ${args[@]} REPO="${REPO}/proxy" publishdevimage
make ${args[@]} REPO="${REPO}/operator" publishdevoperator

if [[ ! -z "$KIND" ]]; then
  kind load docker-image "${REPO}/operator:${VERSION_SHORT}" --name "${KIND}"
  kind load docker-image  "${REPO}/proxy:${VERSION_SHORT}" --name "${KIND}"
fi

kubectl apply -f ./cmd/k8s-operator/deploy/crds/

helm upgrade \
  --install \
    operator ./cmd/k8s-operator/deploy/chart \
  --namespace tailscale \
  --create-namespace \
  --set operator.image.repo="${REPO}/operator" \
  --set operator.image.tag="${VERSION_SHORT} \
  --set opertor.image.pullPolicy="IfNotPresent" \
  --set proxy.image.repo="${REPO}/proxy \
  --set proxy.image.tag="${VERSION_SHORT}" \
  --set installCRDs=false \
  --set-string apiServerProxyConfig.mode="true" \
  --set oauth.clientId="${OAUTH_CLIENT_ID}" \
  --set oauth.clientSecret="${OAUTH_CLIENT_SECRET}" \
  --set operatorConfig.logging=debug \
  --wait

# ingress-nginx is used in tests.
# Note that this command CANNOT be ran with --wait as the Service will never
# become ready (load balancer cannot be provisioned on kind).
helm upgrade --install ingress ingress-nginx/ingress-nginx

# TODO: either wait for the ingress-controller Pod to become ready or do
# something else to wait for the parts we care about to be ready.
