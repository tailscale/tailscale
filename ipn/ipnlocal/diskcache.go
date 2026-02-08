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
