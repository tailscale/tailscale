// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package posture

import (
	"fmt"

	"github.com/StackExchange/wmi"
)

type Win32_BIOS struct {
	SerialNumber string
}

type Win32_BIOS struct {
	SerialNumber string
}

// GetSerialNumber queries WMI for the availablee serial
// numbers of the current device. This will typically be
// one, however the query _can_ return multiple.
func GetSerialNumber() ([]string, error) {
	var dst []Win32_BIOS
	q := wmi.CreateQuery(&dst, "")
	err := wmi.QueryNamespace(q, &dst, "ROOT\\CIMV2")
	if err != nil {
		return nil, fmt.Errorf(
			"failed to query Windows Management Instrumentation for BIOS info status: %w",
			err,
		)
	}

	ret := make([]string, len(dst))
	for i, v := range dst {
		ret[i] = v.SerialNumber
	}

	return ret, nil
}
