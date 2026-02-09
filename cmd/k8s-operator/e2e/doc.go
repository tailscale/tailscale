// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package e2e runs end-to-end tests for the Tailscale Kubernetes operator.
//
// To run without arguments, it requires:
//
// * Kubernetes cluster with local kubeconfig for it (direct connection, no API server proxy)
// * Tailscale operator installed with --set apiServerProxyConfig.mode="true"
// * ACLs from acl.hujson
// * OAuth client secret in TS_API_CLIENT_SECRET env, with at least auth_keys write scope and tag:k8s tag
// * Default ProxyClass and operator env vars as appropriate to set the desired default proxy images.
//
// It also supports running against devcontrol, using the --devcontrol flag,
// which it expects to reach at http://localhost:31544. Use --cluster to create
// a dedicated kind cluster for the tests, and --build to build and test the
// operator and proxy images for the current checkout.
//
// To run with minimal dependencies, use:
//
// go test -count=1 -v ./cmd/k8s-operator/e2e/ --build --cluster --devcontrol --skip-cleanup
//
// Running like this, it requires:
//
// * go
// * container runtime with the docker daemon API available
// * devcontrol: ./tool/go run --tags=tailscale_saas ./cmd/devcontrol --generate-test-devices=k8s-operator-e2e --scenario-output-dir=/tmp/k8s-operator-e2e --test-dns=http://localhost:8055
package e2e
