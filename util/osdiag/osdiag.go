// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package osdiag provides loggers for OS-specific diagnostic information.
package osdiag

// LogSupportInfoReason is an enumeration indicating the reason for logging
// support info.
type LogSupportInfoReason int

const (
	LogSupportInfoReasonStartup   LogSupportInfoReason = iota + 1 // tailscaled is starting up.
	LogSupportInfoReasonBugReport                                 // a bugreport is in the process of being gathered.
)

// SupportInfo obtains OS-specific diagnostic information for troubleshooting
// and support. The reason governs the verbosity of the output.
func SupportInfo(reason LogSupportInfoReason) map[string]any {
	return supportInfo(reason)
}
