// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package syspolicy contains the implementation of system policy management.
// Calling code should use the client interface in
// tailscale.com/util/syspolicy/policyclient.
package syspolicy

import (
	"errors"
	"fmt"
	"reflect"
	"time"

	"tailscale.com/util/syspolicy/internal/loggerx"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
	"tailscale.com/util/syspolicy/ptype"
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

// hasAnyOf returns whether at least one of the specified policy settings is configured,
// or an error if no keys are provided or the check fails.
func hasAnyOf(keys ...pkey.Key) (bool, error) {
	if len(keys) == 0 {
		return false, errors.New("at least one key must be specified")
	}
	policy, err := rsop.PolicyFor(setting.DefaultScope())
	if err != nil {
		return false, err
	}
	effective := policy.Get()
	for _, k := range keys {
		_, err := effective.GetErr(k)
		if errors.Is(err, setting.ErrNotConfigured) || errors.Is(err, setting.ErrNoSuchKey) {
			continue
		}
		if err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// getString returns a string policy setting with the specified key,
// or defaultValue if it does not exist.
func getString(key pkey.Key, defaultValue string) (string, error) {
	return getCurrentPolicySettingValue(key, defaultValue)
}

// getUint64 returns a numeric policy setting with the specified key,
// or defaultValue if it does not exist.
func getUint64(key pkey.Key, defaultValue uint64) (uint64, error) {
	return getCurrentPolicySettingValue(key, defaultValue)
}

// getBoolean returns a boolean policy setting with the specified key,
// or defaultValue if it does not exist.
func getBoolean(key pkey.Key, defaultValue bool) (bool, error) {
	return getCurrentPolicySettingValue(key, defaultValue)
}

// getStringArray returns a multi-string policy setting with the specified key,
// or defaultValue if it does not exist.
func getStringArray(key pkey.Key, defaultValue []string) ([]string, error) {
	return getCurrentPolicySettingValue(key, defaultValue)
}

// getPreferenceOption loads a policy from the registry that can be
// managed by an enterprise policy management system and allows administrative
// overrides of users' choices in a way that we do not want tailcontrol to have
// the authority to set. It describes user-decides/always/never options, where
// "always" and "never" remove the user's ability to make a selection. If not
// present or set to a different value, defaultValue (and a nil error) is returned.
func getPreferenceOption(name pkey.Key, defaultValue ptype.PreferenceOption) (ptype.PreferenceOption, error) {
	return getCurrentPolicySettingValue(name, defaultValue)
}

// getVisibility loads a policy from the registry that can be managed
// by an enterprise policy management system and describes show/hide decisions
// for UI elements. The registry value should be a string set to "show" (return
// true) or "hide" (return true). If not present or set to a different value,
// "show" (return false) is the default.
func getVisibility(name pkey.Key) (ptype.Visibility, error) {
	return getCurrentPolicySettingValue(name, ptype.VisibleByPolicy)
}

// getDuration loads a policy from the registry that can be managed
// by an enterprise policy management system and describes a duration for some
// action. The registry value should be a string that time.ParseDuration
// understands. If the registry value is "" or can not be processed,
// defaultValue is returned instead.
func getDuration(name pkey.Key, defaultValue time.Duration) (time.Duration, error) {
	d, err := getCurrentPolicySettingValue(name, defaultValue)
	if err != nil {
		return d, err
	}
	if d < 0 {
		return defaultValue, nil
	}
	return d, nil
}

// registerChangeCallback adds a function that will be called whenever the effective policy
// for the default scope changes. The returned function can be used to unregister the callback.
func registerChangeCallback(cb rsop.PolicyChangeCallback) (unregister func(), err error) {
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
func getCurrentPolicySettingValue[T setting.ValueType](key pkey.Key, def T) (T, error) {
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

func init() {
	policyclient.RegisterClientImpl(globalSyspolicy{})
}

// globalSyspolicy implements [policyclient.Client] using the syspolicy global
// functions and global registrations.
//
// TODO: de-global-ify. This implementation using the old global functions
// is an intermediate stage while changing policyclient to be modular.
type globalSyspolicy struct{}

func (globalSyspolicy) GetBoolean(key pkey.Key, defaultValue bool) (bool, error) {
	return getBoolean(key, defaultValue)
}

func (globalSyspolicy) GetString(key pkey.Key, defaultValue string) (string, error) {
	return getString(key, defaultValue)
}

func (globalSyspolicy) GetStringArray(key pkey.Key, defaultValue []string) ([]string, error) {
	return getStringArray(key, defaultValue)
}

func (globalSyspolicy) SetDebugLoggingEnabled(enabled bool) {
	loggerx.SetDebugLoggingEnabled(enabled)
}

func (globalSyspolicy) GetUint64(key pkey.Key, defaultValue uint64) (uint64, error) {
	return getUint64(key, defaultValue)
}

func (globalSyspolicy) GetDuration(name pkey.Key, defaultValue time.Duration) (time.Duration, error) {
	return getDuration(name, defaultValue)
}

func (globalSyspolicy) GetPreferenceOption(name pkey.Key, defaultValue ptype.PreferenceOption) (ptype.PreferenceOption, error) {
	return getPreferenceOption(name, defaultValue)
}

func (globalSyspolicy) GetVisibility(name pkey.Key) (ptype.Visibility, error) {
	return getVisibility(name)
}

func (globalSyspolicy) HasAnyOf(keys ...pkey.Key) (bool, error) {
	return hasAnyOf(keys...)
}

func (globalSyspolicy) RegisterChangeCallback(cb func(policyclient.PolicyChange)) (unregister func(), err error) {
	return registerChangeCallback(cb)
}
