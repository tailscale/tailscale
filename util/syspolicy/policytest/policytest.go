// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package policytest contains test helpers for the syspolicy packages.
package policytest

import (
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"tailscale.com/util/set"
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
// expected type and/or value. Some accessors such as GetPreferenceOption and
// GetVisibility support either a ptype.PreferenceOption/ptype.Visibility in the
// map, or the string representation as supported by their UnmarshalText
// methods.
//
// The map value may be an error to return that error value from the accessor.
type Config map[pkey.Key]any

var _ policyclient.Client = Config{}

// Set sets key to value. The value should be of the correct type that it will
// be read as later. For PreferenceOption and Visibility, you may also set them
// to 'string' values and they'll be UnmarshalText'ed into their correct value
// at Get time.
//
// As a special case, the value can also be of type error to make the accessors
// return that error value.
func (c *Config) Set(key pkey.Key, value any) {
	if *c == nil {
		*c = make(map[pkey.Key]any)
	}
	(*c)[key] = value

	if w, ok := (*c)[watchersKey].(*watchers); ok && key != watchersKey {
		w.mu.Lock()
		vals := slices.Collect(maps.Values(w.s))
		w.mu.Unlock()
		for _, f := range vals {
			f(policyChange(key))
		}
	}
}

// SetMultiple is a batch version of [Config.Set]. It copies the contents of o
// into c and does at most one notification wake-up for the whole batch.
func (c *Config) SetMultiple(o Config) {
	if *c == nil {
		*c = make(map[pkey.Key]any)
	}

	maps.Copy(*c, o)

	if w, ok := (*c)[watchersKey].(*watchers); ok {
		w.mu.Lock()
		vals := slices.Collect(maps.Values(w.s))
		w.mu.Unlock()
		for _, f := range vals {
			f(policyChanges(o))
		}
	}
}

type policyChange pkey.Key

func (pc policyChange) HasChanged(v pkey.Key) bool { return pkey.Key(pc) == v }
func (pc policyChange) HasChangedAnyOf(keys ...pkey.Key) bool {
	return slices.Contains(keys, pkey.Key(pc))
}

type policyChanges map[pkey.Key]any

func (pc policyChanges) HasChanged(v pkey.Key) bool {
	_, ok := pc[v]
	return ok
}
func (pc policyChanges) HasChangedAnyOf(keys ...pkey.Key) bool {
	for _, k := range keys {
		if pc.HasChanged(k) {
			return true
		}
	}
	return false
}

const watchersKey = "_policytest_watchers"

type watchers struct {
	mu sync.Mutex
	s  set.HandleSet[func(policyclient.PolicyChange)]
}

// EnableRegisterChangeCallback makes c support the RegisterChangeCallback
// for testing. Without calling this, the RegisterChangeCallback does nothing.
// For watchers to be notified, use the [Config.Set] method. Changing the map
// directly obviously wouldn't work.
func (c *Config) EnableRegisterChangeCallback() {
	if _, ok := (*c)[watchersKey]; !ok {
		c.Set(watchersKey, new(watchers))
	}
}

func (c Config) GetStringArray(key pkey.Key, defaultVal []string) ([]string, error) {
	if val, ok := c[key]; ok {
		switch val := val.(type) {
		case []string:
			return val, nil
		case error:
			return nil, val
		default:
			panic(fmt.Sprintf("key %s is not a []string; got %T", key, val))
		}
	}
	return defaultVal, nil
}

func (c Config) GetString(key pkey.Key, defaultVal string) (string, error) {
	if val, ok := c[key]; ok {
		switch val := val.(type) {
		case string:
			return val, nil
		case error:
			return "", val
		default:
			panic(fmt.Sprintf("key %s is not a string; got %T", key, val))
		}
	}
	return defaultVal, nil
}

func (c Config) GetBoolean(key pkey.Key, defaultVal bool) (bool, error) {
	if val, ok := c[key]; ok {
		switch val := val.(type) {
		case bool:
			return val, nil
		case error:
			return false, val
		default:
			panic(fmt.Sprintf("key %s is not a bool; got %T", key, val))
		}
	}
	return defaultVal, nil
}

func (c Config) GetUint64(key pkey.Key, defaultVal uint64) (uint64, error) {
	if val, ok := c[key]; ok {
		switch val := val.(type) {
		case uint64:
			return val, nil
		case error:
			return 0, val
		default:
			panic(fmt.Sprintf("key %s is not a uint64; got %T", key, val))
		}
	}
	return defaultVal, nil
}

func (c Config) GetDuration(key pkey.Key, defaultVal time.Duration) (time.Duration, error) {
	if val, ok := c[key]; ok {
		switch val := val.(type) {
		case time.Duration:
			return val, nil
		case error:
			return 0, val
		default:
			panic(fmt.Sprintf("key %s is not a time.Duration; got %T", key, val))
		}
	}
	return defaultVal, nil
}

func (c Config) GetPreferenceOption(key pkey.Key, defaultVal ptype.PreferenceOption) (ptype.PreferenceOption, error) {
	if val, ok := c[key]; ok {
		switch val := val.(type) {
		case ptype.PreferenceOption:
			return val, nil
		case error:
			var zero ptype.PreferenceOption
			return zero, val
		case string:
			var p ptype.PreferenceOption
			err := p.UnmarshalText(([]byte)(val))
			return p, err
		default:
			panic(fmt.Sprintf("key %s is not a ptype.PreferenceOption", key))
		}
	}
	return defaultVal, nil
}

func (c Config) GetVisibility(key pkey.Key) (ptype.Visibility, error) {
	if val, ok := c[key]; ok {
		switch val := val.(type) {
		case ptype.Visibility:
			return val, nil
		case error:
			var zero ptype.Visibility
			return zero, val
		case string:
			var p ptype.Visibility
			err := p.UnmarshalText(([]byte)(val))
			return p, err
		default:
			panic(fmt.Sprintf("key %s is not a ptype.Visibility", key))
		}
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

func (c Config) RegisterChangeCallback(callback func(policyclient.PolicyChange)) (func(), error) {
	w, ok := c[watchersKey].(*watchers)
	if !ok {
		return func() {}, nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	h := w.s.Add(callback)
	return func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		delete(w.s, h)
	}, nil
}

func (sp Config) SetDebugLoggingEnabled(enabled bool) {}
