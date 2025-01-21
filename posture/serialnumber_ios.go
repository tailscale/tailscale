// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package posture

import (
	"fmt"

	"tailscale.com/types/logger"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
)

// GetSerialNumbers returns the serial number of the iOS/tvOS device as reported by an
// MDM solution. It requires configuration via the DeviceSerialNumber system policy.
// This is the only way to gather serial numbers on iOS and tvOS.
func GetSerialNumbers(polc policyclient.Client, _ logger.Logf) ([]string, error) {
	s, err := polc.GetString(pkey.DeviceSerialNumber, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get serial number from MDM: %v", err)
	}
	if s != "" {
		return []string{s}, nil
	}
	return nil, nil
}
