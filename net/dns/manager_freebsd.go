// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"fmt"
	"os"

	"tailscale.com/types/logger"
)

func NewOSConfigurator(logf logger.Logf, _ string) (OSConfigurator, error) {
	bs, err := os.ReadFile("/etc/resolv.conf")
	if os.IsNotExist(err) {
		return newDirectManager(logf), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading /etc/resolv.conf: %w", err)
	}

	switch resolvOwner(bs) {
	case "resolvconf":
		switch resolvconfStyle() {
		case "":
			return newDirectManager(logf), nil
		case "debian":
			return newDebianResolvconfManager(logf)
		case "openresolv":
			return newOpenresolvManager(logf)
		default:
			logf("[unexpected] got unknown flavor of resolvconf %q, falling back to direct manager", resolvconfStyle())
			return newDirectManager(logf), nil
		}
	default:
		return newDirectManager(logf), nil
	}
}
