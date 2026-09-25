// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

// client performs the conn25 functionality for clients of connectors
// It allocates magic and transit IP addresses and communicates them with
// connectors.
// It's safe for concurrent use.
type client struct {
	logf      logger.Logf
	addrsCh   chan addrs
	getIPSets func() ipSets

	// Remember to add new fields to [client.reset] if needed.
	mu              sync.Mutex // protects the fields below
	v4MagicIPPool   *ippool
	v4TransitIPPool *ippool
	v6MagicIPPool   *ippool
	v6TransitIPPool *ippool
	assignments     addrAssignments
	byConnKey       map[key.NodePublic]set.Set[netip.Prefix]
}

// transitIPForMagicIP is part of the implementation of the [Conn25Datapath] interface for dataflow lookups.
// See also [Conn25Datapath.ClientTransitIPForMagicIP].
func (c *client) transitIPForMagicIP(magicIP netip.Addr) (netip.Addr, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.assignments.lookupByMagicIP(magicIP)
	if ok {
		return v.transit, true
	}
	return netip.Addr{}, false
}

// linkLocalAllow returns true if the provided packet with a link-local Dst address has a
// Dst that is one of our transit IPs, and false otherwise.
// Tailscale's wireguard filters drop link-local unicast packets (see [wgengine/filter/filter.go])
// but conn25 uses link-local addresses for transit IPs.
// Let the filter know if this is one of our addresses and should be allowed.
func (c *client) linkLocalAllow(p packet.Parsed) (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ok := c.isKnownTransitIP(p.Dst.Addr())
	if ok {
		return true, packetFilterAllowReason
	}
	return false, ""
}

func (c *client) isKnownTransitIP(tip netip.Addr) bool {
	_, ok := c.assignments.lookupByTransitIP(tip)
	return ok
}

func (c *client) reconfig() {
	c.mu.Lock()
	defer c.mu.Unlock()

	ipSets := c.getIPSets()

	c.v4MagicIPPool = c.v4MagicIPPool.reconfig(ipSets.v4Magic)
	c.v4TransitIPPool = c.v4TransitIPPool.reconfig(ipSets.v4Transit)
	c.v6MagicIPPool = c.v6MagicIPPool.reconfig(ipSets.v6Magic)
	c.v6TransitIPPool = c.v6TransitIPPool.reconfig(ipSets.v6Transit)
}

// reset clears all internal state of [client], that are not configuration
// passed into it.
func (c *client) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	ipSets := c.getIPSets()
	c.v4MagicIPPool = newIPPool(ipSets.v4Magic)
	c.v4TransitIPPool = newIPPool(ipSets.v4Transit)
	c.v6MagicIPPool = newIPPool(ipSets.v6Magic)
	c.v6TransitIPPool = newIPPool(ipSets.v6Transit)
	c.assignments = addrAssignments{clock: c.assignments.clock}
	c.byConnKey = nil
}

// reserveAddresses tries to make an assignment of addrs from the address pools
// for this domain+dst address, so that this client can use conn25 connectors.
// The name of the matching app is also provided, no validation is done to check whether or not
// the app name refers to a configured app.
// It checks that this domain should be routed and that this client is not itself a connector for the domain
// and generally if it is valid to make the assignment.
func (c *client) reserveAddresses(appName string, domain dnsname.FQDN, dst netip.Addr, ttl time.Duration) (*addrs, error) {
	if !dst.IsValid() {
		return nil, errors.New("dst is not valid")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.assignments.lookupByDomainDst(domain, dst); ok {
		c.assignments.updateFromTTL(existing, ttl)
		return existing, nil
	}

	// Before we check out more addresses from the pools try to return some.
	// Trying to return any number greater than 1 will cause the number of
	// addresses used to trend down in general. But as we have 2 different
	// pools for the different IP versions, use a number a bit higher than
	// 2 to try and process bursty behavior faster.
	now := c.assignments.clock.Now()
	for range 10 {
		a := c.assignments.popExpired(now)
		if a == nil {
			break
		}
		if a.is4() {
			c.v4MagicIPPool.returnAddr(a.magic)
			c.v4TransitIPPool.returnAddr(a.transit)
		} else if a.is6() {
			c.v6MagicIPPool.returnAddr(a.magic)
			c.v6TransitIPPool.returnAddr(a.transit)
		} else {
			return nil, errors.New("unexpected neither 4 nor 6")
		}
	}

	var mip, tip netip.Addr
	var err error
	if dst.Is4() {
		mip, err = c.v4MagicIPPool.next()
		if err != nil {
			return nil, err
		}
		tip, err = c.v4TransitIPPool.next()
		if err != nil {
			return nil, err
		}
	} else if dst.Is6() {
		mip, err = c.v6MagicIPPool.next()
		if err != nil {
			return nil, err
		}
		tip, err = c.v6TransitIPPool.next()
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("unexpected neither 4 nor 6")
	}
	as := &addrs{
		dst:     dst,
		magic:   mip,
		transit: tip,
		app:     appName,
		domain:  domain,
	}
	if err := c.assignments.insertFromTTL(as, ttl); err != nil {
		return nil, err
	}
	err = c.enqueueAddressAssignment(as)
	if err != nil {
		return nil, err
	}
	return as, nil
}

func (c *client) addTransitIPForConnector(tip netip.Addr, conn tailcfg.NodeView) error {
	if conn.Key().IsZero() {
		return fmt.Errorf("node with stable ID %q does not have a key", conn.StableID())
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	return c.insertTransitConnMapping(tip, conn.Key())
}

func (c *client) enqueueAddressAssignment(addrs *addrs) error {
	select {
	// TODO(fran) investigate the value of waiting for multiple addresses and sending them
	// in one ConnectorTransitIPRequest
	case c.addrsCh <- *addrs:
		return nil
	default:
		c.logf("address assignment queue full, dropping transit assignment for %v", addrs.domain)
		return errors.New("queue full")
	}
}

func (c *client) flowCreated(transit netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.assignments.byTransitIP[transit]
	if !ok {
		return
	}
	entry.activeFlowCount++
}

func (c *client) flowRemoved(transit netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.assignments.byTransitIP[transit]
	if !ok {
		return
	}
	entry.activeFlowCount--
	if entry.activeFlowCount == 0 {
		entry.zeroFlowTime = c.assignments.clock.Now()
	}
}

func (c *client) extraWireGuardAllowedIPs(k key.NodePublic) views.Slice[netip.Prefix] {
	c.mu.Lock()
	defer c.mu.Unlock()
	tips, ok := c.lookupTransitIPsByConnKey(k)
	if !ok {
		return views.Slice[netip.Prefix]{}
	}
	return views.SliceOf(tips)
}

func (c *client) rewriteDNSResponse(appName string, hdr dnsmessage.Header, questions []dnsmessage.Question, answers []dnsResponseRewrite) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, hdr)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	for _, q := range questions {
		if err := b.Question(q); err != nil {
			return nil, err
		}
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}

	// make an answer for each rewrite
	for _, rw := range answers {
		as, err := c.reserveAddresses(appName, rw.domain, rw.dst, time.Duration(rw.ttlSeconds)*time.Second)
		if err != nil {
			return nil, err
		}
		if !as.isValid() {
			return nil, errors.New("connector addresses empty")
		}
		name, err := dnsmessage.NewName(rw.domain.WithTrailingDot())
		if err != nil {
			return nil, err
		}
		if rw.dst.Is4() {
			rhdr := dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: rw.ttlSeconds}
			if err := b.AResource(rhdr, dnsmessage.AResource{A: as.magic.As4()}); err != nil {
				return nil, err
			}
		} else if rw.dst.Is6() {
			rhdr := dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: rw.ttlSeconds}
			if err := b.AAAAResource(rhdr, dnsmessage.AAAAResource{AAAA: as.magic.As16()}); err != nil {
				return nil, err
			}
		} else {
			return nil, errors.New("unexpected neither 4 nor 6")
		}
	}
	// We do _not_ include the additional section in our rewrite. (We don't want to include
	// eg DNSSEC info, or other extra info like related records).
	out, err := b.Finish()
	if err != nil {
		return nil, err
	}
	return out, nil
}

type addrs struct {
	dst             netip.Addr
	magic           netip.Addr
	transit         netip.Addr
	domain          dnsname.FQDN
	app             string
	expiresAt       time.Time
	activeFlowCount int
	zeroFlowTime    time.Time
}

func (as addrs) isValid() bool {
	return as.dst.IsValid()
}

func (as addrs) is4() bool {
	return as.dst.Is4()
}

func (as addrs) is6() bool {
	return as.dst.Is6()
}

// insertTransitConnMapping adds an entry to the byConnKey map
// for the provided transitIP (as a prefix).
// The provided transitIP must already be present in the byTransitIP map.
func (c *client) insertTransitConnMapping(tip netip.Addr, connKey key.NodePublic) error {
	if _, ok := c.assignments.lookupByTransitIP(tip); !ok {
		return errors.New("transit IP is not already known")
	}

	ctips, ok := c.byConnKey[connKey]
	tipp := netip.PrefixFrom(tip, tip.BitLen())
	if !ok {
		ctips.Make()
		mak.Set(&c.byConnKey, connKey, ctips)
	}
	ctips.Add(tipp)
	return nil
}

// lookupTransitIPsByConnKey returns a slice containing the transit IPs (as netipPrefix)
// associated with the given connector (identified by node key), or (nil, false) if there is no entry
// for the given key.
func (c *client) lookupTransitIPsByConnKey(k key.NodePublic) ([]netip.Prefix, bool) {
	s, ok := c.byConnKey[k]
	if !ok {
		return nil, false
	}
	return s.Slice(), true
}

// resendTransitIPMapping enqueues a request to re-establish an existing
// transit IP-real IP mapping after a connector tells the client that the
// mapping does not exist on its end. If a mapping is not found on the client
// either, this is a no-op.
func (c *client) resendTransitIPMapping(transitIP netip.Addr) {
	mapping, ok := c.assignments.lookupByTransitIP(transitIP)
	if !ok {
		// We have no mappings for this transit IP, so nothing to resend.
		return
	}
	err := c.enqueueAddressAssignment(mapping)
	if err != nil {
		c.logf("error enqueueing address assignment for resend: %v", err)
	}
}
