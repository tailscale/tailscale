// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"tailscale.com/net/tsaddr"
)

// resolverTimeout is how long a single resolver gets to answer. It is well
// under [Timeout], because we may have several to try and the whole lookup
// should still fit inside one detection attempt.
const resolverTimeout = time.Second

// lookupIP resolves host to IPv4 addresses, preferring the resolvers belonging
// to the physical network over whatever the system would use.
//
// The preference is what makes this work at all on a node using an exit node.
// The system resolver there is quad-100, which forwards into the tunnel and out
// the exit node — unreachable, by definition, from behind a captive portal. The
// network's own resolvers are one hop away on the LAN and answer regardless.
// They are also the resolvers whose answers describe the network we are asking
// about, which is the only network any of these probes care about.
//
// The system resolver is still tried last, so a machine where we could not
// identify a local resolver behaves as it always did.
//
// ifIndex, if non-zero, is the interface the queries are bound to.
func (d *Detector) lookupIP(ctx context.Context, host string, ifIndex int) ([]netip.Addr, error) {
	// Each resolver gets its own short deadline, but the search as a whole
	// stays inside the budget one query used to have.
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()

	var firstErr error
	for _, server := range d.localNetworkResolvers() {
		got, err := d.lookupIPVia(ctx, server, host, ifIndex)
		switch {
		case err == nil && len(got) > 0:
			return got, nil
		case isNotFound(err):
			// The resolver answered, and its answer is that the name does not
			// exist. Asking someone else would only get us a fabricated answer
			// from a resolver further away than the one that just spoke.
			return nil, err
		}
		if firstErr == nil && err != nil {
			firstErr = err
		}
		d.logf("[v2] captivedetection: resolver %v did not answer for %q: %v", server, host, err)
	}

	if d.dialFn != nil && d.lookupIPFn == nil {
		// Our sockets aren't using the system's network stack, so the system's
		// resolver isn't on the network we're asking about. Querying it would
		// send a real packet to the real Internet on behalf of a virtual one.
		if firstErr == nil {
			firstErr = errors.New("no local network resolver answered")
		}
		return nil, firstErr
	}

	got, err := d.lookupIPVia(ctx, netip.Addr{}, host, ifIndex)
	if err != nil && firstErr != nil {
		return nil, firstErr
	}
	return got, err
}

// lookupIPVia resolves host using server, or using the system resolver if
// server is the zero Addr.
func (d *Detector) lookupIPVia(ctx context.Context, server netip.Addr, host string, ifIndex int) ([]netip.Addr, error) {
	if d.lookupIPFn != nil {
		return d.lookupIPFn(ctx, server, host)
	}

	r := net.DefaultResolver
	if server.IsValid() {
		// One named server, so a short deadline: it's a hop away, and there may
		// be others to get through. The system resolver, by contrast, gets
		// whatever is left of the caller's budget, as it always did.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, resolverTimeout)
		defer cancel()

		addr := netip.AddrPortFrom(server, 53).String()
		r = &net.Resolver{
			// Force Go's own resolver: cgo's would use the host's
			// configuration, which is the thing we're going around.
			PreferGo: true,
			// Likewise ignore the address it read from that configuration and
			// send the query to the server we were asked for.
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.dialTo(ctx, network, addr, ifIndex)
			},
		}
	}

	// Fully qualify the name so that a search domain can't turn it into a
	// different one that happens to resolve.
	return r.LookupNetIP(ctx, "ip4", fqdn(host))
}

// localNetworkResolvers returns the resolvers belonging to the physical
// network, most authoritative first, with duplicates removed.
func (d *Detector) localNetworkResolvers() []netip.Addr {
	d.mu.Lock()
	fn := d.localResolversFn
	netMon := d.netMon
	d.mu.Unlock()

	var out []netip.Addr
	add := func(ip netip.Addr) {
		ip = ip.Unmap()
		// Quad-100 is the resolver we are specifically trying to get around; it
		// can appear here if the OS configuration was read while Tailscale had
		// already taken DNS over.
		if !ip.IsValid() || ip.IsUnspecified() ||
			ip == tsaddr.TailscaleServiceIP() || ip == tsaddr.TailscaleServiceIPv6() ||
			slices.Contains(out, ip) {
			return
		}
		out = append(out, ip)
	}

	if fn != nil {
		for _, ip := range fn() {
			add(ip)
		}
	}
	// The gateway is the resolver on the overwhelming majority of the networks
	// that have portals, and on some of them it's the only one that will answer
	// before we've logged in. It goes last: it's a guess, where the OS
	// configuration is a statement.
	//
	// Only the monitor is asked, so a test's static monitor keeps this
	// deterministic instead of it depending on the machine the test runs on.
	if netMon != nil {
		if gw, _, ok := netMon.GatewayAndSelfIP(); ok {
			add(gw)
		}
	}
	return out
}

// isNotFound reports whether err is a resolver saying the name does not exist,
// as opposed to not answering at all.
func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// fqdn returns host with a trailing dot, so resolvers treat it as fully
// qualified and don't append search domains to it.
func fqdn(host string) string {
	if strings.HasSuffix(host, ".") {
		return host
	}
	return host + "."
}
