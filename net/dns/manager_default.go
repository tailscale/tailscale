// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !freebsd && !openbsd && !windows && !darwin

package dns

import (
	"tailscale.com/health"
	"tailscale.com/types/logger"
)

func NewOSConfigurator(logger.Logf, *health.Tracker, string) (OSConfigurator, error) {
	return NewNoopManager()
}
