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

// mDNSResponder imposes a 60-second minimum on cached negative answers regardless
// of the TTL in the NXDOMAIN response.
const negativeCacheLifetime = max(negativeTTL, 60*time.Second)

// negativeCache tracks only authoritative NXDOMAINs we generated.
type negativeCache struct {
	mu         sync.Mutex
	generation uint64
	entries    lru.Cache[dnsname.FQDN, time.Time]
	now        func() time.Time // optional test clock, set before use
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
	c.entries.MaxEntries = maxRecentNXDomains
	c.entries.Set(name, c.timeNow())
}

// ClearNegativeCache discards history on a global cache flush or profile change.
func (r *Resolver) ClearNegativeCache() {
	c := &r.negativeCache
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries.Clear()
	c.generation++
}

// CheckCachedDNS reports whether a recent authoritative NXDOMAIN has become
// resolvable. It checks only local host records, including subdomain capability
// handling, and never forwards a query. A match clears the entire history.
func (r *Resolver) CheckCachedDNS() bool {
	c := &r.negativeCache
	c.mu.Lock()
	if c.entries.Len() == 0 {
		c.mu.Unlock()
		return false
	}
	generation := c.generation
	now := c.timeNow()
	var names, expired []dnsname.FQDN
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
	c.mu.Unlock()

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
		c.mu.Lock()
		if c.generation != generation {
			c.mu.Unlock()
			return false
		}
		c.entries.Clear()
		c.generation++
		c.mu.Unlock()
		return true
	}
	return false
}
