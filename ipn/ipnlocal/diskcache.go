// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"errors"
	"fmt"

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
	if err := b.clearStoreLocked(b.currentNode().Context(), store); err != nil {
		b.logf("clearing netmap cache: %v", err)
	}
	b.diskCache = diskCache{} // drop in-memory state
}

// clearStoreLocked discards all the keys in the specified store.
func (b *LocalBackend) clearStoreLocked(ctx context.Context, store netmapcache.Store) error {
	var errs []error
	for key, err := range store.List(ctx, "") {
		if err != nil {
			errs = append(errs, fmt.Errorf("list cache contest: %w", err))
			break
		}
		if err := store.Remove(ctx, key); err != nil {
			errs = append(errs, fmt.Errorf("discard cache key %q: %w", key, err))
		}
	}
	return errors.Join(errs...)
}

// ClearNetmapCache discards stored netmap caches (if any) for profiles for the
// current user of b. It also drops any cache from the active backend session,
// if there is one.
func (b *LocalBackend) ClearNetmapCache(ctx context.Context) error {
	if !buildfeatures.HasCacheNetMap {
		return nil // disabled
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	var errs []error
	for _, p := range b.pm.Profiles() {
		store := netmapcache.FileStore(b.profileDataPathLocked(p.ID(), "netmap-cache"))
		err := b.clearStoreLocked(ctx, store)
		if err != nil {
			errs = append(errs, fmt.Errorf("clear netmap cache for profile %q: %w", p.ID(), err))
		}
	}

	b.diskCache = diskCache{} // drop in-memory state
	return errors.Join(errs...)
}
