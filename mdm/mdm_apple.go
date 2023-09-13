//go:build darwin

package mdm

import (
	"fmt"
	"os/exec"

	"tailscale.com/version"
)

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
		return false, fmt.Errorf("unexpected user defaults value for %v: %v", key, err)
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
