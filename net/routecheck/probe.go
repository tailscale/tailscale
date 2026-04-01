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
	"tailscale.com/tsconst"
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

// DefaultTimeout is the default time allowed for a response
// before a peer is considered unreachable.
const DefaultTimeout = tsconst.DefaultPingTimeout

type probed struct {
	tailcfg.NodeView
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

	timestampProbe := func(n probed) {
		mu.Lock()
		defer mu.Unlock()
		mak.Set(&r.LastProbed, n.ID(), time.Now())
	}

	markReachable := func(n probed) {
		mu.Lock()
		defer mu.Unlock()
		nid := n.ID()
		if _, ok := r.Reachable[nid]; !ok {
			mak.Set(&r.Reachable, nid, Node{
				ID:     nid,
				Name:   n.Name(),
				Addr:   n.addr,
				Routes: n.routes,
			})
		}
	}

	// TODO(sfllaw): Since the nodes are sorted by priority,
	// where earlier nodes have high traffic-steering scores,
	// it should be possible to deprioritize or skip probes
	// if there are already enough responses for a particular resource.
	// This optimization has not been implemented yet, so all nodes are probed.
	for n := range nodes {
		// WireGuard-only nodes are assumed to be reachable, since
		// we don’t want to probe nodes that don’t understand Disco pings.
		//
		// We could establish a WireGuard session to probe them,
		// which would allow us to exclude nodes that won’t respond,
		// but all the other nodes would hold unnecessary session state.
		// This would be incredibly rude and could potentially DDOS them.
		//
		// TODO(sfllaw): Add a mechanism to mark a node as unreachable
		// because it fails of establish a new WireGuard connection.
		if n.IsWireGuardOnly() {
			timestampProbe(n)
			markReachable(n)
			continue
		}

		g.Go(func() error {
			metricPing.Add(1)

			// We record the timestamp of each node’s latest probe
			// so we can probe in incremental batches
			// and to limit the rate that any given node is pinged.
			//
			// TODO(sfllaw): We currently record the timestamp
			// but haven’t implemented batching or rate-limiting yet.
			defer timestampProbe(n)

			// TODO(sfllaw): Why did we choose Disco ping instead of TSMP ping?
			// After all, a TSMP ping proves that the peer Tailscale node is there
			// and that both nodes know each other’s WireGuard keys,
			// while a Disco ping only proves that the peer can be found using DERP.
			// However, TSMP is wrapped in a long-lived WireGuard connection,
			// which is too expensive when generating a reachability report.
			// Although different nodes theoretically could share the same Disco key,
			// in practice there is a 1:1 mapping between a Disco key and a node key.
			//
			// TODO(#19670): WireGuard establishes connections with a single round-trip,
			// so there is no existing way to confirm that a WireGuard connection
			// can be established without burdening the peer with lingering state.
			// WireGuard could be extended with a special `handshake_initiation`
			// that only verifies that a connection could be established,
			// requesting this with a sentinel in `handshake_initiation.mac2`.
			// The peer would send a valid but stateless `handshake_response`,
			// using a random ephemeral_private key and not record any state.
			// See https://www.wireguard.com/protocol/.
			switch pong, err := c.ping(ctx, n.addr, tailcfg.PingDisco, timeout); {
			case err == context.DeadlineExceeded:
				// Ping timed out, so assume that the node is unreachable.
				c.vlogf("ping %s (%s): timed out", n.addr, n.ID())
				metricPingTimeout.Add(1)
				return nil
			case err != nil:
				// Returning an error would cancel the errgroup.
				c.vlogf("ping %s (%s): error: %v", n.addr, n.ID(), err)
				metricPingError.Add(1)
				return nil
			case pong == nil:
				c.vlogf("ping %s (%s): error: no response", n.addr, n.ID())
				metricPingError.Add(1)
				return nil
			default:
				c.vlogf("ping %s (%s): result: %f ms (err: %v)",
					n.addr, n.ID(), pong.LatencySeconds*1000, pong.Err)
				metricPingReachable.Add(1)
			}

			markReachable(n)
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
// A node’s IPv4 address is preferred, if the current node also supports IPv4.
// A node’s IPv6 is only probed when the current node only supports IPv6.
// In 2026, IPv4 is still more common and more likely to work properly.
func (c *Client) Probe(ctx context.Context, nodes iter.Seq[tailcfg.NodeView], limit int, timeout time.Duration) (*Report, error) {
	can4, can6 := supportsIPVersions(c.nb.NodeBackend().Self())
	if !can4 && !can6 {
		return nil, nil
	}
	// TODO(sfllaw): Probes should fall back to IPv6, if the IPv4 probe times out
	// and IPv6 is also supported by the current node.
	addrFor := addrPicker(can4, can6)

	var dsts iter.Seq[probed] = func(yield func(probed) bool) {
		for n := range nodes {
			// Probe one of the tailnet addresses.
			addr := addrFor(n)
			if !addr.IsValid() {
				continue // No valid addresses.
			}
			if !yield(probed{
				NodeView: n,
				addr:     addr,
				routes:   routes(n),
			}) {
				return
			}
		}
	}

	return c.probe(ctx, dsts, limit, timeout)
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

// SupportsIPVersions reports whether n supports IPv4 or IPv6.
func supportsIPVersions(n tailcfg.NodeView) (can4, can6 bool) {
	if !n.Valid() {
		return false, false
	}
	for _, ip := range n.Addresses().All() {
		addr := ip.Addr()
		if addr.Is4() {
			can4 = true
		} else if addr.Is6() {
			can6 = true
		}
		if can4 && can6 {
			break
		}
	}
	return can4, can6
}

func addrPicker(can4, can6 bool) func(n tailcfg.NodeView) netip.Addr {
	// TODO(sfllaw): Picking just the one address is a little brittle
	// because this picks just one address and there’s no fallback facility.
	// [Client.Probe] is the caller that will need refactoring.
	return func(n tailcfg.NodeView) netip.Addr {
		var zero netip.Addr
		for _, ip := range n.Addresses().All() {
			// Find a compatible IP address.
			addr := ip.Addr()
			if can4 && addr.Is4() {
				return addr
			}
			if can6 && addr.Is6() {
				return addr
			}
		}
		return zero
	}
}
