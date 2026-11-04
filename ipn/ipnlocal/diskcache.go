// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"errors"
	"fmt"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn/ipnlocal/netmapcache"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// diskCache is the state netmap caching to disk.
type diskCache struct {
	// all fields guarded by LocalBackend.mu

	dir   string // active profile cache directory
	cache *netmapcache.Cache
}

// writePeerDeltaToDiskLocked applies the specified peer delta to the cache,
// leaving other existing cached fields (self, profiles, other peers not
// mentioned in the arguments) unchanged.  It does nothing (without error) if
// both slices are empty.
func (b *LocalBackend) writePeerDeltaToDiskLocked(update []tailcfg.NodeView, remove []tailcfg.StableNodeID) error {
	if !buildfeatures.HasCacheNetMap || (len(update) == 0 && len(remove) == 0) {
		return nil
	} else if err := b.ensureDiskCacheLocked(); err != nil {
		return err
	}
	// Do not log this, we get deltas all the time and it's very noisy.
	return b.diskCache.cache.UpdatePeers(b.currentNode().Context(), update, remove)
}

// writeNetmapToDiskLockedWithoutPeers updates nm in the cache, excluding peers and profiles.
func (b *LocalBackend) writeNetmapToDiskLockedWithoutPeers(nm *netmap.NetworkMap) error {
	if !buildfeatures.HasCacheNetMap || nm == nil || nm.Cached {
		return nil
	} else if err := b.ensureDiskCacheLocked(); err != nil {
		return err
	}
	b.logf("updating netmap in disk cache")
	return b.diskCache.cache.UpdateSelfOnly(b.currentNode().Context(), b.patchNetmapHomeDERPLocked(nm))
}

// writeNetmapToDiskLockedWithPeers writes nm into the cache, including peers and profiles.
func (b *LocalBackend) writeNetmapToDiskLockedWithPeers(nm *netmap.NetworkMap) error {
	if !buildfeatures.HasCacheNetMap || nm == nil || nm.Cached {
		return nil
	} else if err := b.ensureDiskCacheLocked(); err != nil {
		return err
	}
	b.logf("writing netmap to disk cache")
	return b.diskCache.cache.Store(b.currentNode().Context(), b.patchNetmapHomeDERPLocked(nm))
}

func (b *LocalBackend) patchNetmapHomeDERPLocked(nm *netmap.NetworkMap) *netmap.NetworkMap {
	// Set the homeDERP on the self node before saving. The self node homeDERP is
	// generally not used since the homeDERP for self is stored in magicsock, but
	// to be able to load it during loading the cache, we use the existing field
	// to save it.

	// Make a shallow copy and mutate a copy of the selfNode.
	nmCopy := *nm
	selfNode := nm.SelfNode.AsStruct()
	selfNode.HomeDERP = tailcfg.DERPRegionID(b.currentNode().homeDERP.Load())
	nmCopy.SelfNode = selfNode.View()
	return &nmCopy
}

func (b *LocalBackend) ensureDiskCacheLocked() error {
	dir, err := b.profileMkdirAllLocked(b.pm.CurrentProfile().ID(), "netmap-cache")
	if err != nil {
		return err
	}
	if c := b.diskCache; c.cache == nil || c.dir != dir {
		b.closeDiskCacheLocked() // if we changed the dir, close the previous cache.
		store, err := netmapcache.NewStore(b.ctx, dir)
		if err != nil {
			return fmt.Errorf("unable to open store: %s", err)
		}
		b.diskCache.cache = netmapcache.NewCache(store)
		b.diskCache.dir = dir
	}
	return nil
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
		b.closeDiskCacheLocked() // if we changed the dir, close the previous cache.
		store, err := netmapcache.NewStore(b.currentNode().Context(), dir)
		if err != nil {
			b.logf("unable to open store: %s", err)
			return nil, false
		}
		b.diskCache.cache = netmapcache.NewCache(store)
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
	// Reaching here, we have a cache that needs to be purged.
	// Log errors but do not fail for them. Clear both the configured store and
	// the fallback FileStore. This could be the same store twice, in which case
	// the second clear will do nothing. We do this so that clients built with
	// only the default FileStore support will not persist stale cache data after
	// switching to a different storage implementation.
	if err := b.diskCache.cache.Clear(b.ctx); err != nil {
		b.logf("clearing netmap cache: %v", err)
	}
	store := netmapcache.FileStore(b.diskCache.dir)
	if err := store.Clear(b.ctx); err != nil {
		b.logf("clearing netmap cache: %v", err)
	}
	b.closeDiskCacheLocked()
	b.diskCache = diskCache{} // drop in-memory state
}

func (b *LocalBackend) closeDiskCacheLocked() {
	if b.diskCache.cache == nil {
		return // nothing to do, we do not have a cache
	}
	if err := b.diskCache.cache.Close(b.ctx); err != nil {
		b.logf("error closing cache: %v", err)
	}
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

	// Close the active cache before clearing profiles so we can safely re-open
	// each profile's store. We hold the lock here to ensure no writes happens to
	// the active profile while clearing profiles.
	b.closeDiskCacheLocked()
	b.diskCache = diskCache{}

	var errs []error
	for _, p := range b.pm.Profiles() {
		dir := b.profileDataPathLocked(p.ID(), "netmap-cache")

		// Open and clear the configured store for this profile.
		if store, err := netmapcache.OpenStore(ctx, dir); err != nil {
			errs = append(errs, fmt.Errorf("open store for profile %q: %w", p.ID(), err))
		} else if store == nil {
			continue // store does not exist
		} else {
			if err := store.Clear(ctx); err != nil {
				errs = append(errs, fmt.Errorf("clear netmap cache for profile %q: %w", p.ID(), err))
			}
			store.Close(ctx)
		}

		// Also clear the FileStore as a fallback for file-based entries left over
		// from instances running without a no-file backend.
		if err := netmapcache.FileStore(dir).Clear(ctx); err != nil {
			errs = append(errs, fmt.Errorf("clear file cache for profile %q: %w", p.ID(), err))
		}
	}
	return errors.Join(errs...)
}
