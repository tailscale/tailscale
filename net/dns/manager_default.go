// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build (!linux || android) && !freebsd && !openbsd && !windows && !darwin && !illumos && !solaris && !plan9

package dns

import (
	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/types/logger"
)

// NewOSConfigurator creates a new OS configurator.
//
// The health tracker and the knobs may be nil and are ignored on this platform.
func NewOSConfigurator(logger.Logf, *health.Tracker, *controlknobs.Knobs, string) (OSConfigurator, error) {
	return NewNoopManager()
}
