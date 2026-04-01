// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"cmp"
	"context"
	"iter"
	"net/netip"
	"slices"
	"time"

	"golang.org/x/sync/errgroup"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/traffic"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/mak"
)

var (
	metricPing          = clientmetric.NewCounter("routecheck_ping")
	metricPingError     = clientmetric.NewCounter("routecheck_ping_error")
	metricPingReachable = clientmetric.NewCounter("routecheck_ping_reachable")
	metricPingTimeout   = clientmetric.NewCounter("routecheck_ping_timeout")
	metricProbe         = clientmetric.NewCounter("routecheck_probe")
)

// DefaultTimeout is the default time allowed for a response before a peer is considered unreachable.
const DefaultTimeout = 4 * time.Second

type probed struct {
	id     tailcfg.NodeID
	name   string
	addr   netip.Addr
	routes []netip.Prefix
}

func (c *Client) probe(ctx context.Context, nodes iter.Seq[probed], limit int, timeout time.Duration) (*Report, error) {
	metricProbe.Add(1)

	g, ctx := errgroup.WithContext(ctx)
	if limit > 0 {
		g.SetLimit(limit)
	}

	var mu syncs.Mutex
	r := &Report{}

	// TODO(sfllaw): Since the nodes are sorted by priority,
	// where earlier nodes have high traffic-steering scores,
	// it should be possible to deprioritize or skip probes
	// if there are already enough responses for a particular resource.
	// This optimization has not been implemented yet, so all nodes are probed.
	for n := range nodes {
		g.Go(func() error {
			metricPing.Add(1)
			// TODO(sfllaw): Why did we choose Disco ping instead of TSMP ping?
			// After all, a TSMP ping proves that the peer Tailscale node is there
			// and that both nodes know each other’s WireGuard keys,
			// while a Disco ping only proves that the peer can be found using DERP.
			// However, TSMP is wrapped in a long-lived WireGuard connection,
			// which is too expensive when generating a reachability report.
			//
			// Since WireGuard connections are established using a single round-trip,
			// there is no existing way to confirm that a WireGuard connection
			// can be established without burdening the peer with lingering state.
			// WireGuard could be extended with a special `handshake_initiation`
			// that only verifies that a connection could be established,
			// requesting this with a sentinel in `handshake_initiation.mac2`.
			// The peer would send a valid but stateless `handshake_response`,
			// using a random ephemeral_private key and not record any state.
			// See https://www.wireguard.com/protocol/ and tailscale/tailscale#19670.
			pong, err := c.ping(ctx, n.addr, tailcfg.PingDisco, timeout)
			if err != nil {
				// Returning an error would cancel the errgroup.
				if err != context.DeadlineExceeded {
					c.vlogf("ping %s (%s): error: %v", n.addr, n.id, err)
					metricPingError.Add(1)
				}
				// Ping timed out, so assume that the node is unreachable.
				c.vlogf("ping %s (%s): timed out", n.addr, n.id)
				metricPingTimeout.Add(1)
				return nil
			} else if pong == nil {
				c.vlogf("ping %s (%s): error: no response", n.addr, n.id)
				metricPingError.Add(1)
				return nil
			} else {
				c.vlogf("ping %s (%s): result: %f ms (err: %v)", n.addr, n.id, pong.LatencySeconds*1000, pong.Err)
				metricPingReachable.Add(1)
			}

			mu.Lock()
			defer mu.Unlock()
			if _, ok := r.Reachable[n.id]; !ok {
				mak.Set(&r.Reachable, n.id, Node{
					ID:     n.id,
					Name:   n.name,
					Addr:   n.addr,
					Routes: n.routes,
				})
			}
			return nil
		})
	}
	g.Wait()
	r.Done = time.Now()
	return r, nil
}

// Probe actively probes the sequence of nodes and returns a reachability [Report].
// If limit is positive, it limits the number of concurrent active probes;
// a limit of zero will ping every node at once.
// A peer is considered unreachable if it doesn’t respond within the timeout.
//
// This function will probe nodes in order, so better candidates should be
// sorted earlier in the sequence. This function may use ordering to skip some probes
// if it has discovered enough reachable peers.
//
// This function tries both the IPv4 and IPv6 addresses.
func (c *Client) Probe(ctx context.Context, nodes iter.Seq[tailcfg.NodeView], limit int, timeout time.Duration) (*Report, error) {
	is4, is6 := supportsIPVersions(c.nb.NodeBackend().Self())
	if is4 == nil && is6 == nil {
		return nil, nil
	}
	addrFor := addrPicker(is4, is6)

	// Assumed nodes are ones that we assume are reachable,
	// because we can’t probe nodes that don’t understand Disco pings.
	var assumed []tailcfg.NodeView

	var dsts iter.Seq[probed] = func(yield func(probed) bool) {
		for n := range nodes {
			if n.IsWireGuardOnly() {
				assumed = append(assumed, n)
				continue // Probably can’t speak Disco or DERP.
			}

			// Probe one of the tailnet addresses.
			addr := addrFor(n)
			if !addr.IsValid() {
				continue // No valid addresses.
			}
			if !yield(probed{
				id:     n.ID(),
				name:   n.Name(),
				addr:   addr,
				routes: routes(n),
			}) {
				return
			}
		}
	}

	r, err := c.probe(ctx, dsts, limit, timeout)
	if err != nil {
		return nil, err
	}

	// Mix in the assumed nodes.
	for _, n := range assumed {
		addr := addrFor(n)
		if !addr.IsValid() {
			continue // No valid addresses.
		}
		id := n.ID()
		if _, ok := r.Reachable[id]; !ok {
			mak.Set(&r.Reachable, id, Node{
				ID:     id,
				Name:   n.Name(),
				Addr:   addr,
				Routes: routes(n),
			})
		}
	}
	return r, nil
}

// ProbeAllHARouters actively probes all High Availability routers in parallel
// and returns a [Report] that identifies which of these routers are reachable.
// If limit is positive, it limits the number of concurrent active probes;
// a limit of zero will ping every candidate at once.
// A peer is considered unreachable if it doesn’t respond within the timeout.
func (c *Client) ProbeAllHARouters(ctx context.Context, limit int, timeout time.Duration) (*Report, error) {
	nm, err := c.waitForNetMap(ctx)
	if err != nil {
		return nil, err
	}

	// When a prefix is routed by multiple nodes, we probe those nodes.
	// There is no point to probing a router when it is the only choice.
	// These nodes are referred to a High Availability (HA) routers.
	var nodes []tailcfg.NodeView
	for _, rs := range c.RoutersByPrefix() {
		if len(rs) <= 1 {
			continue
		}
		nodes = append(nodes, rs...) // Note: this introduces duplicates.
	}

	// Sort by Node.ID and deduplicate to avoid double-probing.
	slices.SortFunc(nodes, func(a, b tailcfg.NodeView) int {
		return cmp.Compare(a.ID(), b.ID())
	})
	nodes = slices.CompactFunc(nodes, func(a, b tailcfg.NodeView) bool {
		return a.ID() == b.ID()
	})

	// Each node should probe starting with the highest scoring node.
	// We use rendezvous hashing to break ties in a consistent manner
	// while still preventing swarming.
	ss := traffic.ScoresFor(nm.SelfNode.ID(), nodes)
	ss.SortNodes(nodes)

	return c.Probe(ctx, slices.Values(nodes), limit, timeout)
}

// Ping returns the result of a ping to the peer handling the given IP.
// It returns a [context.DeadlineExceeded] error if the peer doesn’t respond within the timeout.
func (c *Client) ping(ctx context.Context, ip netip.Addr, pingType tailcfg.PingType, timeout time.Duration) (*ipnstate.PingResult, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan *ipnstate.PingResult, 1)
	c.pinger.Ping(ip, pingType, 0, func(pr *ipnstate.PingResult) {
		select {
		case ch <- pr:
		default:
		}
	})
	select {
	case pr := <-ch:
		return pr, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func supportsIPVersions(n tailcfg.NodeView) (is4, is6 func(netip.Addr) bool) {
	if !n.Valid() {
		return nil, nil
	}
	for _, ip := range n.Addresses().All() {
		addr := ip.Addr()
		if addr.Is4() {
			is4 = func(addr netip.Addr) bool { return addr.Is4() }
		} else if addr.Is6() {
			is6 = func(addr netip.Addr) bool { return addr.Is6() }
		}
		if is4 != nil && is6 != nil {
			break
		}
	}
	return is4, is6
}

func addrPicker(is4, is6 func(netip.Addr) bool) func(n tailcfg.NodeView) netip.Addr {
	return func(n tailcfg.NodeView) netip.Addr {
		var zero netip.Addr
		for _, ip := range n.Addresses().All() {
			// Find a compatible IP address.
			addr := ip.Addr()
			if is4 != nil && is4(addr) {
				return addr
			}
			if is6 != nil && is6(addr) {
				return addr
			}
		}
		return zero
	}
}
