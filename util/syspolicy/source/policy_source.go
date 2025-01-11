// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package source defines interfaces for policy stores,
// facilitates the creation of policy sources, and provides
// functionality for reading policy settings from these sources.
package source

import (
	"errors"

	"tailscale.com/util/syspolicy/setting"
)

// ErrStoreClosed is an error returned when attempting to use a [Store] after it
// has been closed.
var ErrStoreClosed = errors.New("the policy store has been closed")

// Store provides methods to read system policy settings from OS-specific storage.
// Implementations must be concurrency-safe, and may also implement
// [Lockable], [Changeable], [Expirable] and [io.Closer].
//
// If a [Store] implementation also implements [io.Closer],
// it will be called by the package to release the resources
// when the store is no longer needed.
type Store interface {
	// ReadString returns the value of a [setting.StringValue] with the specified key,
	// an [setting.ErrNotConfigured] if the policy setting is not configured, or
	// an error on failure.
	ReadString(key setting.Key) (string, error)
	// ReadUInt64 returns the value of a [setting.IntegerValue] with the specified key,
	// an [setting.ErrNotConfigured] if the policy setting is not configured, or
	// an error on failure.
	ReadUInt64(key setting.Key) (uint64, error)
	// ReadBoolean returns the value of a [setting.BooleanValue] with the specified key,
	// an [setting.ErrNotConfigured] if the policy setting is not configured, or
	// an error on failure.
	ReadBoolean(key setting.Key) (bool, error)
	// ReadStringArray returns the value of a [setting.StringListValue] with the specified key,
	// an [setting.ErrNotConfigured] if the policy setting is not configured, or
	// an error on failure.
	ReadStringArray(key setting.Key) ([]string, error)
}

// Lockable is an optional interface that [Store] implementations may support.
// Locking a [Store] is not mandatory as [Store] must be concurrency-safe,
// but is recommended to avoid issues where consecutive read calls for related
// policies might return inconsistent results if a policy change occurs between
// the calls. Implementations may use locking to pre-read policies or for
// similar performance optimizations.
type Lockable interface {
	// Lock acquires a read lock on the policy store,
	// ensuring the store's state remains unchanged while locked.
	// Multiple readers can hold the lock simultaneously.
	// It returns an error if the store cannot be locked.
	Lock() error
	// Unlock unlocks the policy store.
	// It is a run-time error if the store is not locked on entry to Unlock.
	Unlock()
}

// Changeable is an optional interface that [Store] implementations may support
// if the policy settings they contain can be externally changed after being initially read.
type Changeable interface {
	// RegisterChangeCallback adds a function that will be called
	// whenever there's a policy change in the [Store].
	// The returned function can be used to unregister the callback.
	RegisterChangeCallback(callback func()) (unregister func(), err error)
}

// Expirable is an optional interface that [Store] implementations may support
// if they can be externally closed or otherwise become invalid while in use.
type Expirable interface {
	// Done returns a channel that is closed when the policy [Store] should no longer be used.
	// It should return nil if the store never expires.
	Done() <-chan struct{}
}
