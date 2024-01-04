// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package osdiag provides loggers for OS-specific diagnostic information.
package osdiag

import "tailscale.com/types/logger"

// LogSupportInfoReason is an enumeration indicating the reason for logging
// support info.
type LogSupportInfoReason int

const (
	LogSupportInfoReasonStartup   LogSupportInfoReason = iota + 1 // tailscaled is starting up.
	LogSupportInfoReasonBugReport                                 // a bugreport is in the process of being gathered.
)

// LogSupportInfo obtains OS-specific diagnostic information useful for
// troubleshooting and support, and writes it to logf. The reason argument is
// useful for governing the verbosity of this function's output.
func LogSupportInfo(logf logger.Logf, reason LogSupportInfoReason) {
	logSupportInfo(logf, reason)
}
