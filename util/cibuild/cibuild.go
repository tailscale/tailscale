// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package cibuild reports runtime CI information.
package cibuild

import "os"

// On reports whether the current binary is executing on a CI system.
func On() bool {
	// CI env variable is set by GitHub.
	// https://docs.github.com/en/actions/learn-github-actions/environment-variables#default-environment-variables
	return os.Getenv("GITHUB_ACTIONS") != "" || os.Getenv("CI") == "true"
}

// OnTailscaleCI reports whether the current binary is executing on
// tailscale/tailscale's own GitHub Actions CI, as opposed to a fork's CI
// or an unrelated downstream CI (such as a Linux distribution's package
// build infrastructure) that also sets the generic CI=true environment
// variable.
func OnTailscaleCI() bool {
	// GITHUB_REPOSITORY_OWNER is set by GitHub Actions to the owner of
	// the repository whose workflow is running. For pull requests, this
	// is the base repository's owner, not the fork's.
	return os.Getenv("GITHUB_REPOSITORY_OWNER") == "tailscale"
}
