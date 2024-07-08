#!/usr/bin/env sh

set -eu

helm uninstall operator --namespace tailscale

kubectl delete -f ./cmd/k8s-operator/deploy/crds

helm uninstall ingress
