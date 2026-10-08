// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || ios

package resolver

import (
	"sync"
	"time"

	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/lru"
)

const maxRecentNXDomains = 4096

// Apple resolvers impose a 60-second minimum on cached negative answers.
const negativeCacheLifetime = max(negativeTTL, 60*time.Second)

// negativeCache tracks only authoritative NXDOMAINs we actually generated.
// It is compiled only on macOS and iOS.
type negativeCache struct {
	// mu guards generation and entries.
	mu sync.Mutex

	// generation advances whenever history is cleared. A check snapshots it
	// before resolving names without mu held, then uses it to avoid requesting
	// a flush if another check or reset has already cleared that history.
	generation uint64

	// entries maps each name to the time of its latest authoritative NXDOMAIN.
	// The LRU bounds memory use; expired entries are pruned when taking a snapshot.
	entries lru.Cache[dnsname.FQDN, time.Time]

	// now is an optional test clock, set before use and never changed concurrently.
	now func() time.Time
}

func (c *negativeCache) timeNow() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *negativeCache) record(name dnsname.FQDN) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Initialize lazily so the zero-value cache is ready to use. Clear preserves
	// MaxEntries, so this is only needed on the first record.
	if c.entries.MaxEntries == 0 {
		c.entries.MaxEntries = maxRecentNXDomains
	}
	c.entries.Set(name, c.timeNow())
}

func (c *negativeCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries.Clear()
	c.generation++
}

// snapshot prunes expired entries and returns recent names with the generation
// they belong to. Callers may resolve these names without holding mu.
func (c *negativeCache) snapshot() (names []dnsname.FQDN, generation uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	generation = c.generation
	if c.entries.Len() == 0 {
		return nil, generation
	}
	now := c.timeNow()
	var expired []dnsname.FQDN
	c.entries.ForEach(func(name dnsname.FQDN, at time.Time) {
		age := now.Sub(at)
		if age >= 0 && age < negativeCacheLifetime {
			names = append(names, name)
		} else {
			expired = append(expired, name)
		}
	})
	for _, name := range expired {
		c.entries.Delete(name)
	}
	return names, generation
}

// clearIfGeneration clears the history only if it has not been cleared since
// the snapshot. It reports whether the caller should request a cache flush.
func (c *negativeCache) clearIfGeneration(generation uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.generation != generation {
		return false
	}
	c.entries.Clear()
	c.generation++
	return true
}

// ClearNegativeCache discards history on a global cache flush or profile change.
func (r *Resolver) ClearNegativeCache() {
	r.negativeCache.clear()
}

// CheckCachedDNS reports whether a recent authoritative NXDOMAIN has become
// resolvable. It checks only local host records, including subdomain capability
// handling, and never forwards a query. A match clears the entire history.
func (r *Resolver) CheckCachedDNS() bool {
	names, generation := r.negativeCache.snapshot()
	// Do not hold the history lock while consulting the live host source.
	for _, name := range names {
		var code dns.RCode
		if dnsname.HasSuffix(name.WithoutTrailingDot(), "arpa") {
			_, code = r.resolveLocalReverse(name)
		} else {
			_, code = r.resolveLocal(name, dns.TypeALL)
		}
		if code != dns.RCodeSuccess {
			continue
		}
		return r.negativeCache.clearIfGeneration(generation)
	}
	return false
}
