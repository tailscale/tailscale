// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_syspolicy

package main

import (
	"tailscale.com/tsd"

	"tailscale.com/util/syspolicy"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
)

func init() {
	initSyspolicy = func(sys *tsd.System) {
		sys.PolicyClient.Set(globalSyspolicy{})
	}
}

// globalSyspolicy implements [policyclient.Client] using
// the syspolicy global functions and global registrations.
//
// TODO: de-global-ify
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

func (globalSyspolicy) RegisterChangeCallback(cb func(policyclient.PolicyChange)) (unregister func(), err error) {
	return syspolicy.RegisterChangeCallback(cb)
}

type PolicyChange interface {
	HasChanged(key pkey.Key) bool
}
