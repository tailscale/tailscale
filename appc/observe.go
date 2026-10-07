// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_appconnectors

package appc

import (
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/util/mak"
)

// ObserveDNSResponse is a callback invoked by the DNS resolver when a DNS
// response is being returned over the PeerAPI. The response is parsed and
// matched against the configured domains, if matched the routeAdvertiser is
// advised to advertise the discovered route.
func (e *AppConnector) ObserveDNSResponse(res []byte) error {
	var p dnsmessage.Parser
	if _, err := p.Start(res); err != nil {
		return err
	}
	if err := p.SkipAllQuestions(); err != nil {
		return err
	}

	// cnameChain tracks a chain of CNAMEs for a given query in order to reverse
	// a CNAME chain back to the original query for flattening. The keys are
	// CNAME record targets, and the value is the name the record answers, so
	// for www.example.com CNAME example.com, the map would contain
	// ["example.com"] = "www.example.com".
	var cnameChain map[string]string

	// addressRecords is a list of address records found in the response.
	type addressRecord struct {
		addr netip.Addr
		ttl  time.Duration
	}
	var addressRecords map[string][]addressRecord
	var cnameTTL time.Duration

	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return err
		}

		if h.Class != dnsmessage.ClassINET {
			if err := p.SkipAnswer(); err != nil {
				return err
			}
			continue
		}

		switch h.Type {
		case dnsmessage.TypeCNAME, dnsmessage.TypeA, dnsmessage.TypeAAAA:
		default:
			if err := p.SkipAnswer(); err != nil {
				return err
			}
			continue

		}

		domain := strings.TrimSuffix(strings.ToLower(h.Name.String()), ".")
		if len(domain) == 0 {
			continue
		}

		if h.Type == dnsmessage.TypeCNAME {
			res, err := p.CNAMEResource()
			if err != nil {
				return err
			}
			cname := strings.TrimSuffix(strings.ToLower(res.CNAME.String()), ".")
			if len(cname) == 0 {
				continue
			}
			mak.Set(&cnameChain, cname, domain)
			cnameTTL = max(cnameTTL, time.Duration(h.TTL)*time.Second)
			continue
		}

		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return err
			}
			addr := netip.AddrFrom4(r.A)
			mak.Set(&addressRecords, domain, append(addressRecords[domain], addressRecord{addr, time.Duration(h.TTL) * time.Second}))
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return err
			}
			addr := netip.AddrFrom16(r.AAAA)
			mak.Set(&addressRecords, domain, append(addressRecords[domain], addressRecord{addr, time.Duration(h.TTL) * time.Second}))
		default:
			if err := p.SkipAnswer(); err != nil {
				return err
			}
			continue
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	expiryChanged := false

	for domain, addrs := range addressRecords {
		domain, isRouted := e.findRoutedDomainLocked(domain, cnameChain)

		// domain and none of the CNAMEs in the chain are routed
		if !isRouted {
			continue
		}

		// advertise each address we have learned for the routed domain, that
		// was not already known.
		var toAdvertise []netip.Prefix
		for _, record := range addrs {
			if !e.isAddrKnownLocked(domain, record.addr) {
				toAdvertise = append(toAdvertise, netip.PrefixFrom(record.addr, record.addr.BitLen()))
			}
			expiryChanged = e.refreshRouteExpiryLocked(domain, record.addr, max(record.ttl, cnameTTL)) || expiryChanged
		}

		if len(toAdvertise) > 0 {
			e.logf("[v2] observed new routes for %s: %s", domain, toAdvertise)
			e.scheduleAdvertisement(domain, toAdvertise...)
		}
	}
	if expiryChanged {
		e.storeRoutesLocked()
	}
	return nil
}
