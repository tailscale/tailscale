// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/envknob"
	"tailscale.com/net/dns/publicdns"
)

// NextDNS answers "dns.nextdns.io" with the unicast IPs of the PoP it picks
// for the asking client, which is often closer than the one anycast routes
// to. See tailscale/tailscale#6130.
const (
	nextDNSSteeringURL   = "https://dns.nextdns.io/"
	nextDNSSteeringName  = "dns.nextdns.io."
	nextDNSLookupTimeout = 5 * time.Second
	nextDNSDialTimeout   = 2 * time.Second
	nextDNSRetryInterval = 10 * time.Minute
	nextDNSMaxTTL        = time.Hour
)

var nextDNSAnycastOnly = envknob.RegisterBool("TS_DEBUG_DNS_NEXTDNS_ANYCAST_ONLY")

// nextDNSSteering is a forwarder's state for sending NextDNS queries to the
// unicast IPs NextDNS steers it to. The unicast IPs serve every NextDNS
// profile, so one state covers them all. It is guarded by forwarder.mu.
type nextDNSSteering struct {
	cur         *steeredClient // or nil to use anycast
	nextRefresh time.Time      // when to next ask NextDNS for unicast IPs
	refreshing  bool           // a refresh is in flight
}

// steeredClient is a DoH client that dials only the unicast ips.
type steeredClient struct {
	client *http.Client
	ips    []netip.Addr // sorted
}

// sendDoHSteered is like sendDoH but, for NextDNS, prefers the steered
// unicast IPs over anycast client c. If they fail, it drops them and sends
// the query over c.
func (f *forwarder) sendDoHSteered(ctx context.Context, urlBase string, c *http.Client, packet []byte) (*Response, error) {
	if !publicdns.IsNextDNS(urlBase) || nextDNSAnycastOnly() {
		return f.sendDoH(ctx, urlBase, c, packet)
	}
	// Refresh after the query, so that a refresh over anycast reuses the
	// query's connection instead of dialing its own.
	defer f.refreshNextDNSSteeringIfDue(c)
	sc := f.steeredNextDNSClient()
	if sc == nil {
		return f.sendDoH(ctx, urlBase, c, packet)
	}
	res, err := f.sendDoH(ctx, urlBase, sc.client, packet)
	if err == nil {
		return res, nil
	}
	if ctx.Err() != nil {
		// A query that ran out of time on the steered IPs drops them, so a
		// PoP that stalls after the handshake costs one query, not every
		// query. A canceled query says nothing about the steered IPs.
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			f.logf("NextDNS via %v timed out, using anycast: %v", sc.ips, err)
			f.dropSteeredNextDNSClient(sc)
		}
		return nil, err
	}
	f.logf("NextDNS via %v failed, using anycast: %v", sc.ips, err)
	f.dropSteeredNextDNSClient(sc)
	return f.sendDoH(ctx, urlBase, c, packet)
}

// steeredNextDNSClient returns the current steered client, or nil if there
// is none.
func (f *forwarder) steeredNextDNSClient() *steeredClient {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nextDNS.cur
}

// refreshNextDNSSteeringIfDue starts a refresh in the background that asks
// NextDNS over anycast client c, if the steering is due for one.
func (f *forwarder) refreshNextDNSSteeringIfDue(c *http.Client) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := &f.nextDNS
	if !s.refreshing && !time.Now().Before(s.nextRefresh) {
		s.refreshing = true
		go f.refreshNextDNSSteering(c, s.cur)
	}
}

// dropSteeredNextDNSClient stops using sc, if it is still the current steered
// client, and waits nextDNSRetryInterval before steering again.
func (f *forwarder) dropSteeredNextDNSClient(sc *steeredClient) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := &f.nextDNS
	if s.cur != sc {
		return
	}
	s.cur = nil
	s.nextRefresh = time.Now().Add(nextDNSRetryInterval)
	sc.client.CloseIdleConnections()
}

// refreshNextDNSSteering asks NextDNS over anycast client c which unicast IPs
// to use and makes a client for them the current steered client. prev is the
// steered client when the refresh started; if a failure dropped it meanwhile,
// the refresh doesn't undo that.
func (f *forwarder) refreshNextDNSSteering(c *http.Client, prev *steeredClient) {
	ctx, cancel := context.WithTimeout(f.ctx, nextDNSLookupTimeout)
	defer cancel()
	ips, ttl, err := f.lookupNextDNSSteering(ctx, c)
	if err != nil {
		f.logf("NextDNS steering: %v", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	s := &f.nextDNS
	s.refreshing = false
	if s.cur != prev {
		return
	}
	if err != nil {
		s.nextRefresh = time.Now().Add(nextDNSRetryInterval)
		return
	}
	s.nextRefresh = time.Now().Add(ttl)
	if prev != nil && slices.Equal(prev.ips, ips) {
		return
	}
	nc, ok := f.newDoHClient(nextDNSSteeringURL, ips, nextDNSDialTimeout)
	if !ok {
		return
	}
	s.cur = &steeredClient{client: nc, ips: ips}
	if prev != nil {
		prev.client.CloseIdleConnections()
	}
}

// lookupNextDNSSteering resolves nextDNSSteeringName over anycast client c,
// returning its sorted unicast IPs and how long they're good for.
func (f *forwarder) lookupNextDNSSteering(ctx context.Context, c *http.Client) (ips []netip.Addr, ttl time.Duration, err error) {
	ttl = nextDNSMaxTTL
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{RecursionDesired: true})
		b.StartQuestions()
		b.Question(dnsmessage.Question{
			Name:  dnsmessage.MustNewName(nextDNSSteeringName),
			Type:  typ,
			Class: dnsmessage.ClassINET,
		})
		q, err := b.Finish()
		if err != nil {
			return nil, 0, err
		}
		res, err := f.sendDoH(ctx, nextDNSSteeringURL, c, q)
		if err != nil {
			return nil, 0, err
		}
		var p dnsmessage.Parser
		h, err := p.Start(res.Bs)
		if err != nil {
			return nil, 0, err
		}
		if h.RCode != dnsmessage.RCodeSuccess {
			return nil, 0, fmt.Errorf("%v %v: %v", nextDNSSteeringName, typ, h.RCode)
		}
		if err := p.SkipAllQuestions(); err != nil {
			return nil, 0, err
		}
		answers, err := p.AllAnswers()
		if err != nil {
			return nil, 0, err
		}
		for _, a := range answers {
			ttl = min(ttl, time.Duration(a.Header.TTL)*time.Second)
			var ip netip.Addr
			switch r := a.Body.(type) {
			case *dnsmessage.AResource:
				ip = netip.AddrFrom4(r.A)
			case *dnsmessage.AAAAResource:
				ip = netip.AddrFrom16(r.AAAA)
			}
			if ip.IsGlobalUnicast() && !ip.IsPrivate() && !publicdns.IPIsDoHOnlyServer(ip) {
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) == 0 {
		return nil, 0, errors.New("no unicast IPs for " + nextDNSSteeringName)
	}
	slices.SortFunc(ips, netip.Addr.Compare)
	return slices.Compact(ips), max(ttl, nextDNSRetryInterval), nil
}
