// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"cmp"
	"context"
	"iter"
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"

	"golang.org/x/sync/errgroup"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/util/mak"
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
	g, ctx := errgroup.WithContext(ctx)
	if limit > 0 {
		g.SetLimit(limit)
	}

	var mu syncs.Mutex
	r := &Report{}
	for n := range nodes {
		g.Go(func() error {
			pong, err := c.ping(ctx, n.addr, timeout)
			if err != nil {
				// Returning an error would cancel the errgroup.
				c.vlogf("ping %s (%s): error: %v", n.addr, n.id, err)
				return nil
			} else if pong == nil {
				c.vlogf("ping %s (%s): error: no response", n.addr, n.id)
				return nil
			} else {
				c.vlogf("ping %s (%s): result: %f ms (err: %v)", n.addr, n.id, pong.LatencySeconds*1000, pong.Err)
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
// This function tries both the IPv4 and IPv6 addresses
func (c *Client) Probe(ctx context.Context, nodes iter.Seq[tailcfg.NodeView], limit int, timeout time.Duration) (*Report, error) {
	var canIPv4, canIPv6 bool
	for _, ip := range c.nb.NodeBackend().Self().Addresses().All() {
		addr := ip.Addr()
		if addr.Is4() {
			canIPv4 = true
		} else if addr.Is6() {
			canIPv6 = true
		}
	}

	var dsts iter.Seq[probed] = func(yield func(probed) bool) {
		for n := range nodes {
			// Ping one of the tailnet addresses.
			for _, ip := range n.Addresses().All() {
				// Skip this probe if there is an IP version mismatch.
				addr := ip.Addr()
				if addr.Is4() && !canIPv4 {
					continue
				}
				if addr.Is6() && !canIPv6 {
					continue
				}

				if !yield(probed{
					id:     n.ID(),
					name:   n.Name(),
					addr:   addr,
					routes: routes(n),
				}) {
					return
				}
				break // We only need one address for every node.
			}
		}
	}
	return c.probe(ctx, dsts, limit, timeout)
}

// ProbeAllPeers actively probes all peers in parallel and returns a [Report]
// that identifies which nodes are reachable. If limit is positive, it limits
// the number of concurrent active probes; a limit of zero will ping every
// candidate at once.
// A peer is considered unreachable if it doesn’t respond within the timeout.
func (c *Client) ProbeAllPeers(ctx context.Context, limit int, timeout time.Duration) (*Report, error) {
	nm, err := c.nm.WaitForNetMap(ctx)
	if err != nil {
		return nil, err
	}
	return c.Probe(ctx, slices.Values(nm.Peers), limit, timeout)
}

// ProbeAllHARouters actively probes all High Availability routers in parallel
// and returns a [Report] that identifies which of these routers are reachable.
// If limit is positive, it limits the number of concurrent active probes;
// a limit of zero will ping every candidate at once.
// A peer is considered unreachable if it doesn’t respond within the timeout.
func (c *Client) ProbeAllHARouters(ctx context.Context, limit int, timeout time.Duration) (*Report, error) {
	nm, err := c.nm.WaitForNetMap(ctx)
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

	// To prevent swarming, each node should probe in a different order.
	seed := uint64(nm.SelfNode.ID())
	rnd := rand.New(rand.NewPCG(seed, seed))
	rnd.Shuffle(len(nodes), func(i, j int) {
		nodes[i], nodes[j] = nodes[j], nodes[i]
	})

	return c.Probe(ctx, slices.Values(nodes), limit, timeout)
}

// Ping returns the result of a TSMP ping to the peer handling the given IP.
// It returns a [context.DeadlineExceeded] error if the peer doesn’t respond within the timeout.
func (c *Client) ping(ctx context.Context, ip netip.Addr, timeout time.Duration) (*ipnstate.PingResult, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan *ipnstate.PingResult, 1)
	c.pinger.Ping(ip, tailcfg.PingTSMP, 0, func(pr *ipnstate.PingResult) {
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
