// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build race

package version

// IsRace reports whether the current binary was built with the Go
// race detector enabled.
func IsRace() bool { return true }
