// Copyright (c) Tailscale Inc & AUTHORS
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
