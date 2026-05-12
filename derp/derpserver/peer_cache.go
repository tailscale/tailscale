// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derpserver

import (
	"time"

	"tailscale.com/envknob"
	"tailscale.com/types/key"
)

const (
	// DefaultPeerCacheMaxEntries is the default maximum number of local
	// destination peers cached per sclient.
	DefaultPeerCacheMaxEntries = 100

	// DefaultPeerCacheMaxIdle is the default duration a cached peer can go
	// unused before it is trimmed during the next peer cache cleanup.
	DefaultPeerCacheMaxIdle = 10 * time.Minute

	// defaultPeerCacheLastUsedUpdateInterval is the minimum interval between
	// lastUsed timestamp writes for a hot cached peer.
	defaultPeerCacheLastUsedUpdateInterval = 30 * time.Second
)

var debugDisablePeerCache = envknob.RegisterBool("TS_DEBUG_DERP_DISABLE_PEER_CACHE")

// peerCacheConfig holds the configuration for the per-client peer lookup cache.
type peerCacheConfig struct {
	maxEntries int           // negative is disabled, zero means [DefaultPeerCacheMaxEntries]
	maxIdle    time.Duration // zeros means [DefaultPeerCacheMaxIdle]
}

// SetPeerCacheConfig configures the per-client peer lookup cache.
//
// maxEntries is the maximum number of local destination peers cached per
// sclient. maxIdle is how long a cached peer can go unused before it is trimmed
// during the next peer cache cleanup. Zero values mean to use defaults.
// A negative maxEntries disables the peer cache.
func (s *Server) SetPeerCacheConfig(maxEntries int, maxIdle time.Duration) {
	s.peerCacheConfig = peerCacheConfig{
		maxEntries: maxEntries,
		maxIdle:    maxIdle,
	}
}

func (c peerCacheConfig) effectiveMaxEntries() int {
	if c.maxEntries == 0 {
		return DefaultPeerCacheMaxEntries
	}
	return c.maxEntries
}

func (c peerCacheConfig) effectiveMaxIdle() time.Duration {
	if c.maxIdle <= 0 {
		return DefaultPeerCacheMaxIdle
	}
	return c.maxIdle
}

func (c peerCacheConfig) effectiveLastUsedUpdateEvery() time.Duration {
	maxIdle := c.effectiveMaxIdle()
	if maxIdle < defaultPeerCacheLastUsedUpdateInterval {
		return maxIdle
	}
	return defaultPeerCacheLastUsedUpdateInterval
}

func (s *Server) peerCacheEnabled() bool {
	return s.peerCacheConfig.effectiveMaxEntries() > 0
}

// cachedPeer is the value type stored in [sclient.peerCache].
//
// The cs pointer itself is immutable for the life of the cachedPeer value. The
// pointed-to clientSet is still live state: its activeClient pointer is updated
// atomically, and its dup state is guarded by Server.mu.
//
// lastUsed is intentionally coarse. On a hot cache hit, lookupDestCached reads
// it every time but only writes it when it is older than
// Server.peerCacheConfig.effectiveLastUsedUpdateEvery. The pointer lets value
// copies returned from the LRU share a single timestamp without doing another
// cache Set on the hot path.
//
// A cached clientSet can outlive its entry in Server.clients. That is okay:
// unregisterClient clears activeClient before deleting the clientSet from the
// global map. If the same public key later gets a new clientSet in
// Server.clients, the old cached clientSet will have no active client, causing
// lookupDestCached to miss and lookupDest to replace the cache
// entry with the newer clientSet.
type cachedPeer struct {
	cs       *clientSet
	lastUsed *time.Time
}

// lookupDest returns the local client, mesh forwarder, or duplicate-client
// count for dst.
//
// It must only be called from the [sclient.run] goroutine.
func (c *sclient) lookupDest(dst key.NodePublic) (_ *sclient, fwd PacketForwarder, dstLen int) {
	if c.s.peerCacheEnabled() && !debugDisablePeerCache() {
		if dstClient, ok := c.lookupDestCached(dst); ok {
			// No metric in the hit path for performance; it's redundant with
			// packets_received minus peer_lookup_cache_misses anyway.
			return dstClient, nil, 0
		}
		c.s.peerLookupCacheMisses.Add(1)
	}

	dstClient, fwd, dstLen, set := c.lookupDestUncached(dst)
	if dstClient != nil && c.s.peerCacheEnabled() && !debugDisablePeerCache() {
		c.cacheDest(dst, set)
	}
	return dstClient, fwd, dstLen
}

// lookupDestCached is the hot-path destination lookup used by
// handleFrameSendPacket. It serves repeated sends to known-local peers without
// taking Server.mu by consulting c.peerCache and revalidating the cached
// clientSet through its atomic activeClient pointer.
//
// It returns ok false on cache misses and inactive cached clientSets. It does
// not perform authoritative lookup, duplicate-client accounting, mesh forwarder
// lookup, or cache population; lookupDest handles those on the fallback path.
func (c *sclient) lookupDestCached(dst key.NodePublic) (_ *sclient, ok bool) {
	if peer, ok := c.peerCache.GetOk(dst); ok {
		if dst := peer.cs.activeClient.Load(); dst != nil {
			now := c.s.clock.Now()
			if now.Sub(*peer.lastUsed) > c.s.peerCacheConfig.effectiveLastUsedUpdateEvery() {
				*peer.lastUsed = now
			}
			// Common case for hot local flows: we know the clientSet and no
			// server mutex is needed.
			return dst, true
		}
	}
	return nil, false
}

func (c *sclient) cacheDest(dst key.NodePublic, set *clientSet) {
	now := c.s.clock.Now()
	c.peerCache.Set(dst, cachedPeer{
		cs:       set,
		lastUsed: &now,
	})
	if c.peerCache.Len() > c.s.peerCacheConfig.effectiveMaxEntries() {
		c.peerCache.DeleteOldest()
	}
}

// lookupDestUncached is the authoritative destination lookup. It takes
// Server.mu to read Server.clients and Server.clientsMesh, returning the
// current local client, mesh forwarder, duplicate-client count, and clientSet
// found for dst. The returned clientSet is non-nil only when the returned local
// client is non-nil, and is suitable for cacheDest. At most one of the
// returned clientSet and PacketForwarder can be non-nil: local clients win over
// mesh forwarding, and mesh forwarding is considered only when there is no
// local clientSet.
func (c *sclient) lookupDestUncached(dst key.NodePublic) (_ *sclient, fwd PacketForwarder, dstLen int, cs *clientSet) {
	s := c.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if set, ok := s.clients[dst]; ok {
		dstLen = set.Len()
		if dst := set.activeClient.Load(); dst != nil {
			return dst, nil, dstLen, set
		}
	}
	if dstLen < 1 {
		fwd = s.clientsMesh[dst]
	}
	return nil, fwd, dstLen, nil
}

func (c *sclient) cleanPeerCache() {
	now := c.s.clock.Now()
	var old []key.NodePublic
	c.peerCache.ForEach(func(k key.NodePublic, peer cachedPeer) {
		if now.Sub(*peer.lastUsed) > c.s.peerCacheConfig.effectiveMaxIdle() {
			old = append(old, k)
		}
	})
	for _, k := range old {
		c.peerCache.Delete(k)
	}
}
