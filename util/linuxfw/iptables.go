// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// TODO(#8502): add support for more architectures
//go:build linux && (arm64 || amd64)

package linuxfw

import (
	"tailscale.com/types/logger"
)

// DebugNetfilter prints debug information about iptables rules to the
// provided log function.
func DebugIptables(logf logger.Logf) error {
	// unused.
	return nil
}

// DetectIptables returns the number of iptables rules that are present in the
// system, ignoring the default "ACCEPT" rule present in the standard iptables
// chains.
//
// It only returns an error when the kernel returns an error (i.e. when a
// syscall fails); when there are no iptables rules, it is valid for this
// function to return 0, nil.
func DetectIptables() (int, error) {
	panic("unused")
}
