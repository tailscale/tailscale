// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"

	"tailscale.com/atomicfile"
	"tailscale.com/ipn"
	"tailscale.com/util/winutil/policy"
)

const (
	legacyPrefsFile                  = "prefs"
	legacyPrefsMigrationSentinelFile = "_migrated-to-profiles"
	legacyPrefsExt                   = ".conf"
)

var errAlreadyMigrated = errors.New("profile migration already completed")

func legacyPrefsDir(uid ipn.WindowsUserID) (string, error) {
	// TODO(aaron): Ideally we'd have the impersonation token for the pipe's
	// client and use it to call SHGetKnownFolderPath, thus yielding the correct
	// path without having to make gross assumptions about directory names.
	usr, err := user.LookupId(string(uid))
	if err != nil {
		return "", err
	}
	if usr.HomeDir == "" {
		return "", fmt.Errorf("user %q does not have a home directory", uid)
	}
	userLegacyPrefsDir := filepath.Join(usr.HomeDir, "AppData", "Local", "Tailscale")
	return userLegacyPrefsDir, nil
}

func (pm *profileManager) loadLegacyPrefs(uid ipn.WindowsUserID) (string, ipn.PrefsView, error) {
	userLegacyPrefsDir, err := legacyPrefsDir(uid)
	if err != nil {
		pm.dlogf("no legacy preferences directory for %q: %v", uid, err)
		return "", ipn.PrefsView{}, err
	}

	migrationSentinel := filepath.Join(userLegacyPrefsDir, legacyPrefsMigrationSentinelFile+legacyPrefsExt)
	// verify that migration sentinel is not present
	_, err = os.Stat(migrationSentinel)
	if err == nil {
		pm.dlogf("migration sentinel %q already exists", migrationSentinel)
		return "", ipn.PrefsView{}, errAlreadyMigrated
	}
	if !os.IsNotExist(err) {
		pm.dlogf("os.Stat(%q) = %v", migrationSentinel, err)
		return "", ipn.PrefsView{}, err
	}

	prefsPath := filepath.Join(userLegacyPrefsDir, legacyPrefsFile+legacyPrefsExt)
	prefs, err := ipn.LoadPrefsWindows(prefsPath)
	pm.dlogf("ipn.LoadPrefs(%q) = %v, %v", prefsPath, prefs, err)
	if errors.Is(err, fs.ErrNotExist) {
		return "", ipn.PrefsView{}, errAlreadyMigrated
	}
	if err != nil {
		return "", ipn.PrefsView{}, err
	}

	prefs.ControlURL = policy.SelectControlURL(defaultPrefs.ControlURL(), prefs.ControlURL)

	pm.logf("migrating Windows profile to new format")
	return migrationSentinel, prefs.View(), nil
}

func (pm *profileManager) completeMigration(migrationSentinel string) {
	atomicfile.WriteFile(migrationSentinel, []byte{}, 0600)
}
