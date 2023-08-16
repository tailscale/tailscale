// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package cache contains an interface for a cache around a typed value, and
// various cache implementations that implement that interface.
package cache

import "time"

// Cache is the interface for the cache types in this package.
//
// Functions in this interface take a key parameter, but it is valid for a
// cache type to hold a single value associated with a key, and simply drop the
// cached value if provided with a different key.
//
// It is valid for Cache implementations to be concurrency-safe or not, and
// each implementation should document this. If you need a concurrency-safe
// cache, an existing cache can be wrapped with a lock using NewLocking(inner).
//
// K and V should be types that can be successfully passed to json.Marshal.
type Cache[K comparable, V any] interface {
	// Get should return a previously-cached value or call the provided
	// FillFunc to obtain a new one. The provided key can be used either to
	// allow multiple cached values, or to drop the cache if the key
	// changes; either is valid.
	Get(K, FillFunc[V]) (V, error)

	// Forget should remove the given key from the cache, if it is present.
	// If it is not present, nothing should be done.
	Forget(K)

	// Empty should empty the cache such that the next call to Get should
	// call the provided FillFunc for all possible keys.
	Empty()
}

// FillFunc is the signature of a function for filling a cache. It should
// return the value to be cached, the time that the cached value is valid
// until, or an error.
type FillFunc[T any] func() (T, time.Time, error)
