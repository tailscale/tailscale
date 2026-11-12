// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package e2e runs end-to-end tests for the Tailscale Kubernetes operator.
//
// There are two modes, one mode can run at a time:
//
//   - Standard mode (default): runs the full suite against the operator's
//     managed resources.
//   - Upgrade/downgrade mode (--from-version set): runs only
//     TestOperatorVersionChange, which installs the operator at one version,
//     changes it to another, and asserts the managed resources stay healthy
//     across the change. The rest of the suite is skipped, since this mode
//     installs and upgrades the operator and can conflict with other tests.
//
// The standard-mode requirements and flags are described first, followed by
// upgrade/downgrade mode.
//
// # Standard mode
//
// To run without arguments, it requires:
//
// * Kubernetes cluster with local kubeconfig for it (direct connection, no API server proxy)
// * Tailscale operator installed with --set apiServerProxyConfig.mode="true"
// * ACLs from acl.hujson
// * OAuth client secret in TS_API_CLIENT_SECRET env, with at least auth_keys write and services read scopes, and tag:k8s tag
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
//
// # Upgrade/downgrade mode
//
// This mode runs TestOperatorVersionChange and skips the rest of the suite. The
// operator is installed at --from-version and then changed to --to-version. Each
// takes any git ref - a version tag, commit SHA, or "HEAD" for the current
// checkout. --round-trip then changes back to --from-version in the same run,
// exercising the change in both directions. The test is direction-neutral: pass
// the older version as --from-version for an upgrade, or as --to-version for a
// downgrade.
//
// For example, to upgrade from a released version to the current checkout against
// devcontrol:
//
// go test -v ./cmd/k8s-operator/e2e/ --build --cluster --devcontrol --from-version=v1.104.7 --to-version=HEAD
//
// To test an upgrade/downgrade round-trip against a real cluster and tailnet:
//
// go test -v ./cmd/k8s-operator/e2e/ --build --registry my-registry --from-version=v1.104.7 --to-version=HEAD --round-trip
package e2e
