// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package resolver

import (
	"strings"
	"sync"
	"time"

	dns "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/envknob"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/lru"
)

// Some networks (notably in-flight Wi-Fi captive portals) sinkhole DNS for
// particular domains: they answer A/AAAA queries with NOERROR but hand back
// only the unspecified address (0.0.0.0 or ::) instead of REFUSED/NXDOMAIN or
// the real address. Because the response is a "success", the forwarder's race
// machinery has nothing better to fall back to, and the client can't connect.
//
// The last-known-good cache works around this for an allowlist of domains: when
// forwarding succeeds with a real address, the response is remembered; when a
// later lookup for an allowlisted name is sinkholed (or forwarding fails
// outright), the remembered response is served instead so the name keeps
// resolving to the address it last resolved to.

const (
	// lkgMaxEntries bounds the memory used by the last-known-good cache.
	lkgMaxEntries = 512

	// lkgTTL is how long a remembered response is eligible to be served after
	// it was last stored. It is deliberately generous: the whole point is to
	// survive a hostile network for the length of, say, a flight.
	lkgTTL = 24 * time.Hour
)

// lkgDefaultDomains is the default allowlist suffix set, covering the exact case
// this feature exists for: tailscale.com and its subdomains (e.g.
// console.tailscale.com, login.tailscale.com), which some networks sinkhole.
const lkgDefaultDomains = "tailscale.com"

// lkgDomainsEnv overrides the allowlist. It is a comma-separated list of domain
// suffixes; a name matches if it equals, or is a subdomain of, any suffix. An
// explicit empty value (TS_DNS_LKG_DOMAINS=" ") disables the feature.
var lkgDomainsEnv = envknob.RegisterString("TS_DNS_LKG_DOMAINS")

// lkgKey identifies a cached response by question name and type. Only A and
// AAAA queries are cached, so type is always one of those.
type lkgKey struct {
	name dnsname.FQDN
	typ  dns.Type
}

// lkgEntry is a remembered successful response.
type lkgEntry struct {
	// resp is the full upstream response wire bytes, including its own txid.
	// Callers must patch the txid to match the current query before sending.
	resp []byte
	// at is when the entry was last stored, for TTL expiry.
	at time.Time
}

// lastKnownGood remembers the most recent non-sinkhole response for allowlisted
// names so they can be served when the network later sinkholes or drops them.
//
// The zero value is not usable; use newLastKnownGood.
type lastKnownGood struct {
	// suffixes is the allowlist of domain suffixes, in FQDN form (trailing
	// dot). It is set once at construction and never mutated, so it needs no
	// lock. A nil/empty slice disables the cache.
	suffixes []dnsname.FQDN

	// now is an optional test clock; nil means time.Now.
	now func() time.Time

	mu      sync.Mutex
	entries lru.Cache[lkgKey, lkgEntry]
}

// newLastKnownGood builds a lastKnownGood whose allowlist comes from the
// TS_DNS_LKG_DOMAINS env var, or lkgDefaultDomains if that's unset.
func newLastKnownGood() *lastKnownGood {
	return &lastKnownGood{suffixes: parseLKGDomains(lkgDomainsEnv())}
}

// parseLKGDomains parses a comma-separated suffix list into FQDNs, skipping
// anything that isn't a valid domain name. An unset value (the zero string)
// uses the default; an explicitly non-empty-but-blank value disables matching.
func parseLKGDomains(v string) []dnsname.FQDN {
	if v == "" {
		v = lkgDefaultDomains
	}
	var out []dnsname.FQDN
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		fqdn, err := dnsname.ToFQDN(s)
		if err != nil {
			continue
		}
		out = append(out, fqdn)
	}
	return out
}

func (c *lastKnownGood) timeNow() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// allowed reports whether name is covered by the allowlist. A suffix matches
// itself and any subdomain of it (FQDN.Contains handles both).
func (c *lastKnownGood) allowed(name dnsname.FQDN) bool {
	for _, suffix := range c.suffixes {
		if suffix.Contains(name) {
			return true
		}
	}
	return false
}

// enabled reports whether any name is allowlisted.
func (c *lastKnownGood) enabled() bool { return len(c.suffixes) > 0 }

// store remembers resp as the last-known-good answer for (name, typ) if name is
// allowlisted. resp is retained, so callers must not mutate it afterward.
func (c *lastKnownGood) store(name dnsname.FQDN, typ dns.Type, resp []byte) {
	if !c.allowed(name) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries.MaxEntries == 0 {
		c.entries.MaxEntries = lkgMaxEntries
	}
	c.entries.Set(lkgKey{name, typ}, lkgEntry{resp: resp, at: c.timeNow()})
}

// lookup returns a copy of the remembered response for (name, typ) with txid
// patched into its header, or (nil, false) if there's no live entry or name
// isn't allowlisted. The copy is safe for the caller to send and mutate.
func (c *lastKnownGood) lookup(name dnsname.FQDN, typ dns.Type, txid txid) ([]byte, bool) {
	if !c.allowed(name) {
		return nil, false
	}
	c.mu.Lock()
	ent, ok := c.entries.GetOk(lkgKey{name, typ})
	if ok && c.timeNow().Sub(ent.at) >= lkgTTL {
		c.entries.Delete(lkgKey{name, typ})
		ok = false
	}
	c.mu.Unlock()
	if !ok {
		return nil, false
	}
	out := make([]byte, len(ent.resp))
	copy(out, ent.resp)
	setTxID(out, txid)
	return out, true
}

// lkgLookupOnFail returns a cached last-known-good response for (name, typ) with
// txid patched in, but only when eligible is true. It's a small gate so callers
// in an if/else-if chain can ask for the cache in one expression.
func lkgLookupOnFail(eligible bool, c *lastKnownGood, name dnsname.FQDN, typ dns.Type, id txid) ([]byte, bool) {
	if !eligible {
		return nil, false
	}
	return c.lookup(name, typ, id)
}

// responseHasRealAddr reports whether resp is a NOERROR response carrying at
// least one A or AAAA answer that is not the unspecified address. Only such
// responses are worth remembering as last-known-good; a sinkhole, a no-data
// NOERROR, or an NXDOMAIN is not.
func responseHasRealAddr(resp []byte) bool {
	if getRCode(resp) != dns.RCodeSuccess {
		return false
	}
	var p dns.Parser
	if _, err := p.Start(resp); err != nil {
		return false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return false
	}
	for {
		h, err := p.AnswerHeader()
		if err == dns.ErrSectionDone {
			return false
		}
		if err != nil {
			return false
		}
		switch h.Type {
		case dns.TypeA:
			r, err := p.AResource()
			if err != nil {
				return false
			}
			if r.A != ([4]byte{}) {
				return true
			}
		case dns.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return false
			}
			if r.AAAA != ([16]byte{}) {
				return true
			}
		default:
			if err := p.SkipAnswer(); err != nil {
				return false
			}
		}
	}
}

// isSinkholeResponse reports whether resp is a "sinkhole" answer: a NOERROR
// response with at least one A or AAAA answer where every A/AAAA answer is the
// unspecified address (0.0.0.0 or ::). Non-address records (e.g. CNAME) are
// ignored, so a CNAME chain that terminates only in unspecified addresses still
// counts. A malformed response, or one with no address answers (such as a
// legitimate no-data NOERROR), is not a sinkhole.
func isSinkholeResponse(resp []byte) bool {
	if getRCode(resp) != dns.RCodeSuccess {
		return false
	}
	var p dns.Parser
	if _, err := p.Start(resp); err != nil {
		return false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return false
	}
	sawAddr := false
	for {
		h, err := p.AnswerHeader()
		if err == dns.ErrSectionDone {
			break
		}
		if err != nil {
			return false
		}
		switch h.Type {
		case dns.TypeA:
			r, err := p.AResource()
			if err != nil {
				return false
			}
			if r.A != ([4]byte{}) {
				return false
			}
			sawAddr = true
		case dns.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return false
			}
			if r.AAAA != ([16]byte{}) {
				return false
			}
			sawAddr = true
		default:
			if err := p.SkipAnswer(); err != nil {
				return false
			}
		}
	}
	return sawAddr
}
