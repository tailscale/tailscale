// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package ipnlocal

import (
	"fmt"
	"runtime"

	"tailscale.com/ipn"
	"tailscale.com/version"
)

func (pm *profileManager) loadLegacyPrefs(ipn.WindowsUserID) (string, ipn.PrefsView, error) {
	k := ipn.LegacyGlobalDaemonStateKey
	switch {
	case runtime.GOOS == "ios", version.IsSandboxedMacOS():
		k = "ipn-go-bridge"
	case runtime.GOOS == "android":
		k = "ipn-android"
	}
	prefs, err := pm.loadSavedPrefs(k)
	if err != nil {
		return "", ipn.PrefsView{}, fmt.Errorf("calling ReadState on state store: %w", err)
	}
	pm.logf("migrating %q profile to new format", k)
	return "", prefs, nil
}

func (pm *profileManager) completeMigration(migrationSentinel string) {
	// Do not delete the old state key, as we may be downgraded to an
	// older version that still relies on it.
}
