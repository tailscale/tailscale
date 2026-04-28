// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ios

package ipnlocal

import (
	"context"

	"tailscale.com/ipn/ipnlocal/netmapcache"
	"tailscale.com/types/netmap"
)

// diskCache is the state netmap caching to disk.
type diskCache struct {
}

func (b *LocalBackend) writeNetmapToDiskLocked(nm *netmap.NetworkMap) error {
	return nil // not supported on this platform
}

func (b *LocalBackend) loadDiskCacheLocked() (om *netmap.NetworkMap, ok bool) {
	return nil, false // not supported on this platform
}

// discardDiskCacheLocked removes a cached network map for the current node, if
// one exists, and disables the cache.
func (b *LocalBackend) discardDiskCacheLocked() {}

// clearStoreLocked discards all the keys in the specified store.
func (b *LocalBackend) clearStoreLocked(ctx context.Context, store netmapcache.Store) error {
	return nil // not supported on this platform
}

// ClearNetmapCache discards stored netmap caches (if any) for profiles for the
// current user of b. It also drops any cache from the active backend session,
// if there is one.
func (b *LocalBackend) ClearNetmapCache(ctx context.Context) error {
	return nil // not supported on this platform
}
