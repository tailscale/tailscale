// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ios

package posture

import (
	"fmt"

	"tailscale.com/types/logger"
	"tailscale.com/util/syspolicy"
)

// GetSerialNumber returns the serial number of the iOS device as reported by an
// MDM solution. Requires configuration via the DeviceSerialNumber system policy.
// This is the only way to gather serial numbers on iOS and tvOS.
func GetSerialNumbers(_ logger.Logf) ([]string, error) {
	serials := []string{}

	serialNumberFromMDM, err := syspolicy.GetString("DeviceSerialNumber", "")
	if err != nil {
		return nil, fmt.Errorf("failed to get serial number from MDM: %s", err)
	}

	if serialNumberFromMDM != "" {
		serials = append(serials, serialNumberFromMDM)
	}

	return serials, nil
}
