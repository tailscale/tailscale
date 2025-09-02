// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"fmt"
	"os"

	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/types/logger"
	"tailscale.com/util/syspolicy/policyclient"
)

// NewOSConfigurator creates a new OS configurator.
//
// The health tracker may be nil; the knobs may be nil and are ignored on this platform.
func NewOSConfigurator(logf logger.Logf, health *health.Tracker, _ policyclient.Client, _ *controlknobs.Knobs, _ string) (OSConfigurator, error) {
	bs, err := os.ReadFile("/etc/resolv.conf")
	if os.IsNotExist(err) {
		return newDirectManager(logf, health), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading /etc/resolv.conf: %w", err)
	}

	switch resolvOwner(bs) {
	case "resolvconf":
		switch resolvconfStyle() {
		case "":
			return newDirectManager(logf, health), nil
		case "debian":
			return newDebianResolvconfManager(logf)
		case "openresolv":
			return newOpenresolvManager(logf)
		default:
			logf("[unexpected] got unknown flavor of resolvconf %q, falling back to direct manager", resolvconfStyle())
			return newDirectManager(logf, health), nil
		}
	default:
		return newDirectManager(logf, health), nil
	}
}
