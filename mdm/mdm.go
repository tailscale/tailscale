// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package mdm contains functions to read platform-specific MDM-enforced flags
// in a platform-independent manner.
package mdm

import (
	"fmt"
	"os/exec"
	"runtime"
	"tailscale.com/version"
)

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

/// Darwin

// readUserDefaultsBool reads a boolean value with the given key from the macOS/iOS UserDefaults.
func readUserDefaultsBool(key string) (bool, error) {
	cmd := exec.Command("defaults", "read", userDefaultsDomain(), key)
	output, err := cmd.Output()
	if err != nil {
		return false, err
	}
	asString := string(output)
	if asString == "0" {
		return false, nil
	} else if asString == "1" {
		return true, nil
	} else {
		return false, fmt.Errorf("unexpected user defaults value for", key, ":", err)
	}
}

// readRegistryString reads a string value with the given key from the macOS/iOS UserDefaults.
func readUserDefaultsString(key string) (string, error) {
	cmd := exec.Command("defaults", "read", userDefaultsDomain(), key)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	asString := string(output)
	return asString, nil
}

// userDefaultsDomain returns the domain iOS or macOS store the Tailscale settings in.
func userDefaultsDomain() string {
	var bundleIdentifierSuffix string
	if version.IsMacSysExt() {
		bundleIdentifierSuffix = "macsys"
	} else {
		bundleIdentifierSuffix = "macos"
	}
	return "io.tailscale.ipn." + bundleIdentifierSuffix
}

/// Windows

// readRegistryBool reads a boolean value with the given key from the Windows registry.
func readRegistryBool(key string) (bool, error) {
	// TODO(angott): Windows support
	return false, nil
}

// readRegistryBool reads a string value with the given key from the Windows registry.
func readRegistryString(key string) (string, error) {
	// TODO(angott): Windows support
	return "", nil
}
