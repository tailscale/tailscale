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
	"errors"
	"fmt"
	"reflect"
	"time"

	"tailscale.com/util/syspolicy/internal/loggerx"
	"tailscale.com/util/syspolicy/rsop"
	"tailscale.com/util/syspolicy/setting"
	"tailscale.com/util/syspolicy/source"
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

// RegisterStore registers a new policy [source.Store] with the specified name and [setting.PolicyScope].
//
// It is a shorthand for [rsop.RegisterStore].
func RegisterStore(name string, scope setting.PolicyScope, store source.Store) (*rsop.StoreRegistration, error) {
	return rsop.RegisterStore(name, scope, store)
}

// MustRegisterStoreForTest is like [rsop.RegisterStoreForTest], but it fails the test if the store could not be registered.
func MustRegisterStoreForTest(tb TB, name string, scope setting.PolicyScope, store source.Store) *rsop.StoreRegistration {
	tb.Helper()
	reg, err := rsop.RegisterStoreForTest(tb, name, scope, store)
	if err != nil {
		tb.Fatalf("Failed to register policy store %q as a %v policy source: %v", name, scope, err)
	}
	return reg
}

// GetString returns a string policy setting with the specified key,
// or defaultValue if it does not exist.
func GetString(key Key, defaultValue string) (string, error) {
	return getCurrentPolicySettingValue(key, defaultValue)
}

// GetUint64 returns a numeric policy setting with the specified key,
// or defaultValue if it does not exist.
func GetUint64(key Key, defaultValue uint64) (uint64, error) {
	return getCurrentPolicySettingValue(key, defaultValue)
}

// GetBoolean returns a boolean policy setting with the specified key,
// or defaultValue if it does not exist.
func GetBoolean(key Key, defaultValue bool) (bool, error) {
	return getCurrentPolicySettingValue(key, defaultValue)
}

// GetStringArray returns a multi-string policy setting with the specified key,
// or defaultValue if it does not exist.
func GetStringArray(key Key, defaultValue []string) ([]string, error) {
	return getCurrentPolicySettingValue(key, defaultValue)
}

// GetPreferenceOption loads a policy from the registry that can be
// managed by an enterprise policy management system and allows administrative
// overrides of users' choices in a way that we do not want tailcontrol to have
// the authority to set. It describes user-decides/always/never options, where
// "always" and "never" remove the user's ability to make a selection. If not
// present or set to a different value, "user-decides" is the default.
func GetPreferenceOption(name Key) (setting.PreferenceOption, error) {
	return getCurrentPolicySettingValue(name, setting.ShowChoiceByPolicy)
}

// GetVisibility loads a policy from the registry that can be managed
// by an enterprise policy management system and describes show/hide decisions
// for UI elements. The registry value should be a string set to "show" (return
// true) or "hide" (return true). If not present or set to a different value,
// "show" (return false) is the default.
func GetVisibility(name Key) (setting.Visibility, error) {
	return getCurrentPolicySettingValue(name, setting.VisibleByPolicy)
}

// GetDuration loads a policy from the registry that can be managed
// by an enterprise policy management system and describes a duration for some
// action. The registry value should be a string that time.ParseDuration
// understands. If the registry value is "" or can not be processed,
// defaultValue is returned instead.
func GetDuration(name Key, defaultValue time.Duration) (time.Duration, error) {
	d, err := getCurrentPolicySettingValue(name, defaultValue)
	if err != nil {
		return d, err
	}
	if d < 0 {
		return defaultValue, nil
	}
	return d, nil
}

// RegisterChangeCallback adds a function that will be called whenever the effective policy
// for the default scope changes. The returned function can be used to unregister the callback.
func RegisterChangeCallback(cb rsop.PolicyChangeCallback) (unregister func(), err error) {
	effective, err := rsop.PolicyFor(setting.DefaultScope())
	if err != nil {
		return nil, err
	}
	return effective.RegisterChangeCallback(cb), nil
}

// getCurrentPolicySettingValue returns the value of the policy setting
// specified by its key from the [rsop.Policy] of the [setting.DefaultScope]. It
// returns def if the policy setting is not configured, or an error if it has
// an error or could not be converted to the specified type T.
func getCurrentPolicySettingValue[T setting.ValueType](key Key, def T) (T, error) {
	effective, err := rsop.PolicyFor(setting.DefaultScope())
	if err != nil {
		return def, err
	}
	value, err := effective.Get().GetErr(key)
	if err != nil {
		if errors.Is(err, setting.ErrNotConfigured) || errors.Is(err, setting.ErrNoSuchKey) {
			return def, nil
		}
		return def, err
	}
	if res, ok := value.(T); ok {
		return res, nil
	}
	return convertPolicySettingValueTo(value, def)
}

func convertPolicySettingValueTo[T setting.ValueType](value any, def T) (T, error) {
	// Convert [PreferenceOption], [Visibility], or [time.Duration] back to a string
	// if someone requests a string instead of the actual setting's value.
	// TODO(nickkhyl): check if this behavior is relied upon anywhere besides the old tests.
	if reflect.TypeFor[T]().Kind() == reflect.String {
		if str, ok := value.(fmt.Stringer); ok {
			return any(str.String()).(T), nil
		}
	}
	return def, fmt.Errorf("%w: got %T, want %T", setting.ErrTypeMismatch, value, def)
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

// SetDebugLoggingEnabled controls whether spammy debug logging is enabled.
func SetDebugLoggingEnabled(v bool) {
	loggerx.SetDebugLoggingEnabled(v)
}
