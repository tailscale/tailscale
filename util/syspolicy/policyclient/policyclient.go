// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package policyclient contains the minimal syspolicy interface as needed by
// client code using syspolicy without bringing in the entire syspolicy
// universe.
package policyclient

import "tailscale.com/util/syspolicy/pkey"

type Client interface {
	// GetString returns a string policy setting with the specified key,
	// or defaultValue if it does not exist.
	GetString(key pkey.Key, defaultValue string) (string, error)

	GetStringArray(key pkey.Key, defaultValue []string) ([]string, error)

	GetBoolean(key pkey.Key, defaultValue bool) (bool, error)

	SetDebugLoggingEnabled(enabled bool)

	RegisterChangeCallback(cb func(PolicyChange)) (unregister func(), err error)
}

// NoPolicyClient is a no-op implementation of Client that only
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

func (NoPolicyClient) SetDebugLoggingEnabled(enabled bool) {}

func (NoPolicyClient) RegisterChangeCallback(cb func(PolicyChange)) (unregister func(), err error) {
	return func() {}, nil
}

type PolicyChange interface {
	HasChanged(key pkey.Key) bool
}
