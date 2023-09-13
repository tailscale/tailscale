// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package mdm contains functions to read platform-specific MDM-enforced flags
// in a platform-independent manner.
package mdm

import (
	"fmt"
	"runtime"
)

// MDMSettings gets MDM settings from device.
type MDMSettings interface {
	// ReadBool returns a boolean whether the given MDM key exists or not on device settings.
	ReadBool(key string) (bool, error)
	// ReadString reads the MDM settings value string given the key.
	ReadString(key string) (string, error)
}

func ReadBool(key string) (bool, error) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		return readUserDefaultsBool(key)
	} else if runtime.GOOS == "windows" {
		return readRegistryBool(key)
	} else {
		return false, fmt.Errorf("unsupported platform")
	}
}

func ReadString(key string) (string, error) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		return readUserDefaultsString(key)
	} else if runtime.GOOS == "windows" {
		// TODO(angott): Windows
		return readRegistryString(key)
	} else {
		return "", fmt.Errorf("unsupported platform")
	}
}
