#!/usr/bin/env sh

# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause

set -eu

# This script creates a kind cluster, sets up test dependencies and runs e2e
# tests. It builds the latest operator and proxy image as well as manifests from
# this repo. The operator and proxy images are uploaded to the local container
# registry (i.e docker) and the kind cluster.
#
# Run it with:
# OAUTH_CLIENT_ID=<oauth client ID> \
# OAUTH_CLIENT_SECRET=<oauth-client-secret> \
# [K8S_VERSION=<k8s version>] \
# [CLUSTER_NAME=<cluster_name] \
# ./scripts/kubetests/test_on_kind.sh

K8S_VERSION="${K8S_VERSION:=1.30}"
CLUSTER_NAME="${CLUSTER_NAME:=ts-e2e}"

# Kind recommends to use the exact image SHAs with a given kind build
case  $K8S_VERSION in
1.30*) kind_image=kindest/node:v1.30.0@sha256:047357ac0cfea04663786a612ba1eaba9702bef25227a794b52890dd8bcd692e ;;
1.29*) kind_image=kindest/node:v1.29.4@sha256:3abb816a5b1061fb15c6e9e60856ec40d56b7b52bcea5f5f1350bc6e2320b6f8 ;;
1.28*) kind_image=kindest/node:v1.28.9@sha256:dca54bc6a6079dd34699d53d7d4ffa2e853e46a20cd12d619a09207e35300bd0 ;;
1.27*) kind_image=kindest/node:v1.27.13@sha256:17439fa5b32290e3ead39ead1250dca1d822d94a10d26f1981756cd51b24b9d8 ;;
1.26*) kind_image=kindest/node:v1.26.15@sha256:84333e26cae1d70361bb7339efb568df1871419f2019c80f9a12b7e2d485fe19 ;;
1.25*) kind_image=kindest/node:v1.25.16@sha256:5da57dfc290ac3599e775e63b8b6c49c0c85d3fec771cd7d55b45fae14b38d3b ;;
esac

# TODO: check that the cluster does not already exist
kind create cluster --name "${CLUSTER_NAME}" --image "${kind_image}"

KIND="${CLUSTER_NAME}" OAUTH_CLIENT_ID="${OAUTH_CLIENT_ID}" OAUTH_CLIENT_SECRET="${OAUTH_CLIENT_SECRET}" ./scripts/kubetests/setup.sh

# TODO: now run the tests
# go test ./cmd/k8s-operator/e2e/...
