// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package syspolicy facilitates retrieval of the current policy settings
// applied to the device or user and receiving notifications when the policy
// changes.
//
// It provides functions that return specific policy settings by their unique
// [setting.Key]s, such as [GetBoolean], [GetUint64], [GetString],
// [GetStringArray], [GetPreferenceOption], [GetVisibility] and [GetDuration].
package syspolicy

import (
	"time"

	"tailscale.com/util/syspolicy/setting"
)

var (
	// ErrNotConfigured is returned when the requested policy setting is not configured.
	ErrNotConfigured = setting.ErrNotConfigured
	// ErrTypeMismatch is returned when there's a type mismatch between the actual type
	// of the setting value and the expected type.
	ErrTypeMismatch = setting.ErrTypeMismatch
	// ErrNoSuchKey is returned by [setting.DefinitionOf] when no policy setting
	// has been registered with the specified key.
	//
	// This error is also returned by a (now deprecated) [Handler] when the specified
	// key does not have a value set. While the package maintains compatibility with this
	// usage of ErrNoSuchKey, it is recommended to return [ErrNotConfigured] from newer
	// [source.Store] implementations.
	ErrNoSuchKey = setting.ErrNoSuchKey
)

// GetString returns a string policy setting with the specified key,
// or defaultValue if it does not exist.
func GetString(key Key, defaultValue string) (string, error) {
	return defaultValue, nil
}

// GetUint64 returns a numeric policy setting with the specified key,
// or defaultValue if it does not exist.
func GetUint64(key Key, defaultValue uint64) (uint64, error) {
	return defaultValue, nil
}

// GetBoolean returns a boolean policy setting with the specified key,
// or defaultValue if it does not exist.
func GetBoolean(key Key, defaultValue bool) (bool, error) {
	return defaultValue, nil
}

// GetStringArray returns a multi-string policy setting with the specified key,
// or defaultValue if it does not exist.
func GetStringArray(key Key, defaultValue []string) ([]string, error) {
	return defaultValue, nil
}

// GetVisibility loads a policy from the registry that can be managed
// by an enterprise policy management system and describes show/hide decisions
// for UI elements. The registry value should be a string set to "show" (return
// true) or "hide" (return true). If not present or set to a different value,
// "show" (return false) is the default.
func GetVisibility(name Key) (setting.Visibility, error) {
	return setting.VisibleByPolicy, nil
}

// GetDuration loads a policy from the registry that can be managed
// by an enterprise policy management system and describes a duration for some
// action. The registry value should be a string that time.ParseDuration
// understands. If the registry value is "" or can not be processed,
// defaultValue is returned instead.
func GetDuration(name Key, defaultValue time.Duration) (time.Duration, error) {
	return defaultValue, nil
}

// SelectControlURL returns the ControlURL to use based on a value in
// the registry (LoginURL) and the one on disk (in the GUI's
// prefs.conf). If both are empty, it returns a default value. (It
// always return a non-empty value)
//
// See https://github.com/tailscale/tailscale/issues/2798 for some background.
func SelectControlURL(reg, disk string) string {
	const def = "https://controlplane.tailscale.com"

	// Prior to Dec 2020's commit 739b02e6, the installer
	// wrote a LoginURL value of https://login.tailscale.com to the registry.
	const oldRegDef = "https://login.tailscale.com"

	// If they have an explicit value in the registry, use it,
	// unless it's an old default value from an old installer.
	// Then we have to see which is better.
	if reg != "" {
		if reg != oldRegDef {
			// Something explicit in the registry that we didn't
			// set ourselves by the installer.
			return reg
		}
		if disk == "" {
			// Something in the registry is better than nothing on disk.
			return reg
		}
		if disk != def && disk != oldRegDef {
			// The value in the registry is the old
			// default (login.tailscale.com) but the value
			// on disk is neither our old nor new default
			// value, so it must be some custom thing that
			// the user cares about. Prefer the disk value.
			return disk
		}
	}
	if disk != "" {
		return disk
	}
	return def
}
