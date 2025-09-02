// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package policytest contains test helpers for the syspolicy packages.
package policytest

import (
	"fmt"
	"time"

	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
	"tailscale.com/util/syspolicy/ptype"
)

// Config is a [policyclient.Client] implementation with a static mapping of
// values.
//
// It is used for testing purposes to simulate policy client behavior.
//
// It panics if a value is Set with one type and then accessed with a different
// expected type.
type Config map[pkey.Key]any

var _ policyclient.Client = Config{}

func (c *Config) Set(key pkey.Key, value any) {
	if *c == nil {
		*c = make(map[pkey.Key]any)
	}
	(*c)[key] = value
}

func (c Config) GetStringArray(key pkey.Key, defaultVal []string) ([]string, error) {
	if val, ok := c[key]; ok {
		if arr, ok := val.([]string); ok {
			return arr, nil
		}
		panic(fmt.Sprintf("key %s is not a []string", key))
	}
	return defaultVal, nil
}

func (c Config) GetString(key pkey.Key, defaultVal string) (string, error) {
	if val, ok := c[key]; ok {
		if str, ok := val.(string); ok {
			return str, nil
		}
		panic(fmt.Sprintf("key %s is not a string", key))
	}
	return defaultVal, nil
}

func (c Config) GetBoolean(key pkey.Key, defaultVal bool) (bool, error) {
	if val, ok := c[key]; ok {
		if b, ok := val.(bool); ok {
			return b, nil
		}
		panic(fmt.Sprintf("key %s is not a bool", key))
	}
	return defaultVal, nil
}

func (c Config) GetUint64(key pkey.Key, defaultVal uint64) (uint64, error) {
	if val, ok := c[key]; ok {
		if u, ok := val.(uint64); ok {
			return u, nil
		}
		panic(fmt.Sprintf("key %s is not a uint64", key))
	}
	return defaultVal, nil
}

func (c Config) GetDuration(key pkey.Key, defaultVal time.Duration) (time.Duration, error) {
	if val, ok := c[key]; ok {
		if d, ok := val.(time.Duration); ok {
			return d, nil
		}
		panic(fmt.Sprintf("key %s is not a time.Duration", key))
	}
	return defaultVal, nil
}

func (c Config) GetPreferenceOption(key pkey.Key, defaultVal ptype.PreferenceOption) (ptype.PreferenceOption, error) {
	if val, ok := c[key]; ok {
		if p, ok := val.(ptype.PreferenceOption); ok {
			return p, nil
		}
		panic(fmt.Sprintf("key %s is not a ptype.PreferenceOption", key))
	}
	return defaultVal, nil
}

func (c Config) GetVisibility(key pkey.Key) (ptype.Visibility, error) {
	if val, ok := c[key]; ok {
		if p, ok := val.(ptype.Visibility); ok {
			return p, nil
		}
		panic(fmt.Sprintf("key %s is not a ptype.Visibility", key))
	}
	return ptype.Visibility(ptype.ShowChoiceByPolicy), nil
}

func (c Config) HasAnyOf(keys ...pkey.Key) (bool, error) {
	for _, key := range keys {
		if _, ok := c[key]; ok {
			return true, nil
		}
	}
	return false, nil
}

func (sp Config) RegisterChangeCallback(callback func(policyclient.PolicyChange)) (func(), error) {
	return func() {}, nil
}

func (sp Config) SetDebugLoggingEnabled(enabled bool) {}
