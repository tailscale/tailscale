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
// When building with --build, --base-image overrides the base image that all
// the built images are layered on top of, e.g.
// --base-image=registry.access.redhat.com/ubi9/ubi-minimal:latest. Without it,
// the default base image in build_docker.sh is used. If using a real cluster
// with --build, --registry must also be set.
//
// With --cluster, --cni=cilium creates the kind cluster without its default
// CNI and kube-proxy and installs Cilium from its Helm repository with its
// default data path (eBPF host routing) plus the egress gateway feature and
// tailscale0 among its devices, to exercise the RouteAcceptor's Cilium
// integration. --cilium-set key=value (repeatable) overrides Cilium Helm
// values, e.g. --cilium-set bpf.hostLegacyRouting=true.
//
// --cilium-spike (with --cluster --cni=cilium --build) runs only
// TestCiliumSpike and TestCiliumSpikeSources: they validate the RouteAcceptor's data plane under Cilium
// without devcontrol, a tailnet or the operator, by starting this repository's
// test control server in the test process and deploying the route acceptor
// DaemonSet and a subnet router directly, then trying the Cilium
// configurations of interest one after the other:
//
// go test -count=1 -v -timeout 60m ./cmd/k8s-operator/e2e/ --build --cluster --cni=cilium --cilium-spike --skip-cleanup
//
// --registry without --build expects the images to already exist in the
// registry at the tag derived from the current commit, e.g. pushed by an
// earlier run of tailscale.com/cmd/k8s-operator/e2e/build. That allows one
// build to be shared by test runs against multiple clusters.
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
