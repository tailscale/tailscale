// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn/ipnlocal/netmapcache"
	"tailscale.com/types/netmap"
)

// diskCache is the state netmap caching to disk.
type diskCache struct {
	// all fields guarded by LocalBackend.mu

	dir   string // active profile cache directory
	cache *netmapcache.Cache
}

func (b *LocalBackend) writeNetmapToDiskLocked(nm *netmap.NetworkMap) error {
	if !buildfeatures.HasCacheNetMap || nm == nil || nm.Cached {
		return nil
	}
	b.logf("writing netmap to disk cache")

	dir, err := b.profileMkdirAllLocked(b.pm.CurrentProfile().ID(), "netmap-cache")
	if err != nil {
		return err
	}
	if c := b.diskCache; c.cache == nil || c.dir != dir {
		b.diskCache.cache = netmapcache.NewCache(netmapcache.FileStore(dir))
		b.diskCache.dir = dir
	}
	return b.diskCache.cache.Store(b.currentNode().Context(), nm)
}

func (b *LocalBackend) loadDiskCacheLocked() (om *netmap.NetworkMap, ok bool) {
	if !buildfeatures.HasCacheNetMap {
		return nil, false
	}
	dir, err := b.profileMkdirAllLocked(b.pm.CurrentProfile().ID(), "netmap-cache")
	if err != nil {
		b.logf("profile data directory: %v", err)
		return nil, false
	}
	if c := b.diskCache; c.cache == nil || c.dir != dir {
		b.diskCache.cache = netmapcache.NewCache(netmapcache.FileStore(dir))
		b.diskCache.dir = dir
	}
	nm, err := b.diskCache.cache.Load(b.currentNode().Context())
	if err != nil {
		b.logf("load netmap from cache: %v", err)
		return nil, false
	}
	return nm, true
}

// discardDiskCacheLocked removes a cached network map for the current node, if
// one exists, and disables the cache.
func (b *LocalBackend) discardDiskCacheLocked() {
	if !buildfeatures.HasCacheNetMap {
		return
	}
	if b.diskCache.cache == nil {
		return // nothing to do, we do not have a cache
	}

	// Reaching here, we have a cache directory that needs to be purged.
	// Log errors but do not fail for them.
	store := netmapcache.FileStore(b.diskCache.dir)
	ctx := b.currentNode().Context()
	for key, err := range store.List(ctx, "") {
		if err != nil {
			b.logf("listing cache contents: %v", err)
			break
		}
		if err := store.Remove(ctx, key); err != nil {
			b.logf("discarding cache key %q: %v", key, err)
		}
	}

	b.diskCache.cache = nil // drop reference
	b.diskCache.dir = ""
}
