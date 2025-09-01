// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package policyclient contains the minimal syspolicy interface as needed by
// client code using syspolicy. It's the part that's always linked in, even if the rest
// of syspolicy is omitted from the build.
package policyclient

import "tailscale.com/util/syspolicy/pkey"

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

	// SetDebugLoggingEnabled enables or disables debug logging for the policy client.
	SetDebugLoggingEnabled(enabled bool)

	// RegisterChangeCallback registers a callback function that will be called
	// whenever a policy change is detected. It returns a function to unregister
	// the callback and an error if the registration fails.
	RegisterChangeCallback(cb func(PolicyChange)) (unregister func(), err error)
}

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

func (NoPolicyClient) GetBoolean(key pkey.Key, defaultValue bool) (bool, error) {
	return defaultValue, nil
}

func (NoPolicyClient) GetString(key pkey.Key, defaultValue string) (string, error) {
	return defaultValue, nil
}

func (NoPolicyClient) GetStringArray(key pkey.Key, defaultValue []string) ([]string, error) {
	return defaultValue, nil
}

func (NoPolicyClient) SetDebugLoggingEnabled(enabled bool) {}

func (NoPolicyClient) RegisterChangeCallback(cb func(PolicyChange)) (unregister func(), err error) {
	return func() {}, nil
}
