// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package policyclient contains the minimal syspolicy interface as needed by
// client code using syspolicy. It's the part that's always linked in, even if the rest
// of syspolicy is omitted from the build.
package policyclient

import (
	"time"

	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/ptype"
	"tailscale.com/util/testenv"
)

// Client is the interface between code making questions about the system policy
// and the actual implementation.
type Client interface {
	// GetString returns a string policy setting with the specified key,
	// or defaultValue (and a nil error) if it does not exist.
	GetString(key pkey.Key, defaultValue string) (string, error)

	// GetStringArray returns a string array policy setting with the specified key,
	// or defaultValue (and a nil error) if it does not exist.
	GetStringArray(key pkey.Key, defaultValue []string) ([]string, error)

	// GetBoolean returns a boolean policy setting with the specified key,
	// or defaultValue (and a nil error) if it does not exist.
	GetBoolean(key pkey.Key, defaultValue bool) (bool, error)

	// GetUint64 returns a numeric policy setting with the specified key,
	// or defaultValue (and a nil error) if it does not exist.
	GetUint64(key pkey.Key, defaultValue uint64) (uint64, error)

	// GetDuration loads a policy from the registry that can be managed by an
	// enterprise policy management system and describes a duration for some
	// action. The registry value should be a string that time.ParseDuration
	// understands. If the registry value is "" or can not be processed,
	// defaultValue (and a nil error) is returned instead.
	GetDuration(key pkey.Key, defaultValue time.Duration) (time.Duration, error)

	// GetPreferenceOption loads a policy from the registry that can be
	// managed by an enterprise policy management system and allows administrative
	// overrides of users' choices in a way that we do not want tailcontrol to have
	// the authority to set. It describes user-decides/always/never options, where
	// "always" and "never" remove the user's ability to make a selection. If not
	// present or set to a different value, defaultValue (and a nil error) is returned.
	GetPreferenceOption(key pkey.Key, defaultValue ptype.PreferenceOption) (ptype.PreferenceOption, error)

	// GetVisibility returns whether a UI element should be visible based on
	// the system's configuration.
	// If unconfigured, implementations should return [ptype.VisibleByPolicy]
	// and a nil error.
	GetVisibility(key pkey.Key) (ptype.Visibility, error)

	// SetDebugLoggingEnabled enables or disables debug logging for the policy client.
	SetDebugLoggingEnabled(enabled bool)

	// HasAnyOf returns whether at least one of the specified policy settings is
	// configured, or an error if no keys are provided or the check fails.
	HasAnyOf(keys ...pkey.Key) (bool, error)

	// RegisterChangeCallback registers a callback function that will be called
	// whenever a policy change is detected. It returns a function to unregister
	// the callback and an error if the registration fails.
	RegisterChangeCallback(cb func(PolicyChange)) (unregister func(), err error)
}

// Get returns a non-nil [Client] implementation as a function of the
// build tags. It returns a no-op implementation if the full syspolicy
// package is omitted from the build, or in tests.
func Get() Client {
	if testenv.InTest() {
		// This is a little redundant (the Windows implementation at least
		// already does this) but it's here for redundancy and clarity, that we
		// don't want to accidentally use the real system policy when running
		// tests.
		return NoPolicyClient{}
	}
	return client
}

// RegisterClientImpl registers a [Client] implementation to be returned by
// [Get].
func RegisterClientImpl(c Client) {
	client = c
}

var client Client = NoPolicyClient{}

// PolicyChange is the interface representing a change in policy settings.
type PolicyChange interface {
	// HasChanged reports whether the policy setting identified by the given key
	// has changed.
	HasChanged(pkey.Key) bool

	// HasChangedAnyOf reports whether any of the provided policy settings
	// changed in this change.
	HasChangedAnyOf(keys ...pkey.Key) bool
}

// NoPolicyClient is a no-op implementation of [Client] that only
// returns default values.
type NoPolicyClient struct{}

var _ Client = NoPolicyClient{}

func (NoPolicyClient) GetBoolean(key pkey.Key, defaultValue bool) (bool, error) {
	return defaultValue, nil
}

func (NoPolicyClient) GetString(key pkey.Key, defaultValue string) (string, error) {
	return defaultValue, nil
}

func (NoPolicyClient) GetStringArray(key pkey.Key, defaultValue []string) ([]string, error) {
	return defaultValue, nil
}

func (NoPolicyClient) GetUint64(key pkey.Key, defaultValue uint64) (uint64, error) {
	return defaultValue, nil
}

func (NoPolicyClient) GetDuration(name pkey.Key, defaultValue time.Duration) (time.Duration, error) {
	return defaultValue, nil
}

func (NoPolicyClient) GetPreferenceOption(name pkey.Key, defaultValue ptype.PreferenceOption) (ptype.PreferenceOption, error) {
	return defaultValue, nil
}

func (NoPolicyClient) GetVisibility(name pkey.Key) (ptype.Visibility, error) {
	return ptype.VisibleByPolicy, nil
}

func (NoPolicyClient) HasAnyOf(keys ...pkey.Key) (bool, error) {
	return false, nil
}

func (NoPolicyClient) SetDebugLoggingEnabled(enabled bool) {}

func (NoPolicyClient) RegisterChangeCallback(cb func(PolicyChange)) (unregister func(), err error) {
	return func() {}, nil
}
