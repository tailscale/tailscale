// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_syspolicy

package tsd

import (
	"time"

	"tailscale.com/util/syspolicy"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
	"tailscale.com/util/syspolicy/ptype"
)

func getPolicyClient() policyclient.Client { return globalSyspolicy{} }

// globalSyspolicy implements [policyclient.Client] using the syspolicy global
// functions and global registrations.
//
// TODO: de-global-ify. This implementation using the old global functions
// is an intermediate stage while changing policyclient to be modular.
type globalSyspolicy struct{}

func (globalSyspolicy) GetBoolean(key pkey.Key, defaultValue bool) (bool, error) {
	return syspolicy.GetBoolean(key, defaultValue)
}

func (globalSyspolicy) GetString(key pkey.Key, defaultValue string) (string, error) {
	return syspolicy.GetString(key, defaultValue)
}

func (globalSyspolicy) GetStringArray(key pkey.Key, defaultValue []string) ([]string, error) {
	return syspolicy.GetStringArray(key, defaultValue)
}

func (globalSyspolicy) SetDebugLoggingEnabled(enabled bool) {
	syspolicy.SetDebugLoggingEnabled(enabled)
}

func (globalSyspolicy) GetUint64(key pkey.Key, defaultValue uint64) (uint64, error) {
	return syspolicy.GetUint64(key, defaultValue)
}

func (globalSyspolicy) GetDuration(name pkey.Key, defaultValue time.Duration) (time.Duration, error) {
	return syspolicy.GetDuration(name, defaultValue)
}

func (globalSyspolicy) GetPreferenceOption(name pkey.Key) (ptype.PreferenceOption, error) {
	return syspolicy.GetPreferenceOption(name)
}

func (globalSyspolicy) GetVisibility(name pkey.Key) (ptype.Visibility, error) {
	return syspolicy.GetVisibility(name)
}

func (globalSyspolicy) HasAnyOf(keys ...pkey.Key) (bool, error) {
	return syspolicy.HasAnyOf(keys...)
}

func (globalSyspolicy) RegisterChangeCallback(cb func(policyclient.PolicyChange)) (unregister func(), err error) {
	return syspolicy.RegisterChangeCallback(cb)
}
