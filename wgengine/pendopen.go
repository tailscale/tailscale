// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

import (
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"time"

	"github.com/gaissmai/bart"
	"tailscale.com/net/flowtrack"
	"tailscale.com/net/packet"
	"tailscale.com/net/tstun"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/lazy"
	"tailscale.com/util/mak"
	"tailscale.com/wgengine/filter"
)

const tcpTimeoutBeforeDebug = 5 * time.Second

type pendingOpenFlow struct {
	timer *time.Timer // until giving up on the flow

	// guarded by userspaceEngine.mu:

	// problem is non-zero if we got a MaybeBroken (non-terminal)
	// TSMP "reject" header.
	problem packet.TailscaleRejectReason
}

func (e *userspaceEngine) removeFlow(f flowtrack.Tuple) (removed bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	of, ok := e.pendOpen[f]
	if !ok {
		// Not a tracked flow (likely already removed)
		return false
	}
	of.timer.Stop()
	delete(e.pendOpen, f)
	return true
}

func (e *userspaceEngine) noteFlowProblemFromPeer(f flowtrack.Tuple, problem packet.TailscaleRejectReason) {
	e.mu.Lock()
	defer e.mu.Unlock()
	of, ok := e.pendOpen[f]
	if !ok {
		// Not a tracked flow (likely already removed)
		return
	}
	of.problem = problem
}

func (e *userspaceEngine) trackOpenPreFilterIn(pp *packet.Parsed, t *tstun.Wrapper) (res filter.Response) {
	res = filter.Accept // always

	if pp.IPProto == ipproto.TSMP {
		res = filter.DropSilently
		rh, ok := pp.AsTailscaleRejectedHeader()
		if !ok {
			return
		}
		if rh.MaybeBroken {
			e.noteFlowProblemFromPeer(rh.Flow(), rh.Reason)
		} else if f := rh.Flow(); e.removeFlow(f) {
			e.logf("open-conn-track: flow %v %v > %v rejected due to %v", rh.Proto, rh.Src, rh.Dst, rh.Reason)
		}
		return
	}

	if pp.IPVersion == 0 ||
		pp.IPProto != ipproto.TCP ||
		pp.TCPFlags&(packet.TCPSyn|packet.TCPRst) == 0 {
		return
	}

	// Either a SYN or a RST came back. Remove it in either case.

	f := flowtrack.MakeTuple(pp.IPProto, pp.Dst, pp.Src) // src/dst reversed
	removed := e.removeFlow(f)
	if removed && pp.TCPFlags&packet.TCPRst != 0 {
		e.logf("open-conn-track: flow TCP %v got RST by peer", f)
	}
	return
}

var (
	appleIPRange = netip.MustParsePrefix("17.0.0.0/8")
	canonicalIPs = lazy.SyncFunc(func() (checkIPFunc func(netip.Addr) bool) {
		// https://bgp.he.net/AS41231#_prefixes
		t := &bart.Table[bool]{}
		for _, s := range strings.Fields(`
			91.189.89.0/24
			91.189.91.0/24
			91.189.92.0/24
			91.189.93.0/24
			91.189.94.0/24
			91.189.95.0/24
			162.213.32.0/24
			162.213.34.0/24
			162.213.35.0/24
			185.125.188.0/23
			185.125.190.0/24
			194.169.254.0/24`) {
			t.Insert(netip.MustParsePrefix(s), true)
		}
		return func(ip netip.Addr) bool {
			v, _ := t.Lookup(ip)
			return v
		}
	})
)

// isOSNetworkProbe reports whether the target is likely a network
// connectivity probe target from e.g. iOS or Ubuntu network-manager.
//
// iOS likes to probe Apple IPs on all interfaces to check for connectivity.
// Don't start timers tracking those. They won't succeed anyway. Avoids log
// spam like:
func (e *userspaceEngine) isOSNetworkProbe(dst netip.AddrPort) bool {
	// iOS had log spam like:
	// open-conn-track: timeout opening (100.115.73.60:52501 => 17.125.252.5:443); no associated peer node
	if runtime.GOOS == "ios" && dst.Port() == 443 && appleIPRange.Contains(dst.Addr()) {
		if _, ok := e.PeerForIP(dst.Addr()); !ok {
			return true
		}
	}
	// NetworkManager; https://github.com/tailscale/tailscale/issues/13687
	// open-conn-track: timeout opening (TCP 100.96.229.119:42798 => 185.125.190.49:80); no associated peer node
	if runtime.GOOS == "linux" && dst.Port() == 80 && canonicalIPs()(dst.Addr()) {
		if _, ok := e.PeerForIP(dst.Addr()); !ok {
			return true
		}
	}
	return false
}

func (e *userspaceEngine) trackOpenPostFilterOut(pp *packet.Parsed, t *tstun.Wrapper) (res filter.Response) {
	res = filter.Accept // always

	if pp.IPVersion == 0 ||
		pp.IPProto != ipproto.TCP ||
		pp.TCPFlags&packet.TCPAck != 0 ||
		pp.TCPFlags&packet.TCPSyn == 0 {
		return
	}
	if e.isOSNetworkProbe(pp.Dst) {
		return
	}

	flow := flowtrack.MakeTuple(pp.IPProto, pp.Src, pp.Dst)

	e.mu.Lock()
	defer e.mu.Unlock()
	if _, dup := e.pendOpen[flow]; dup {
		// Duplicates are expected when the OS retransmits. Ignore.
		return
	}

	timer := time.AfterFunc(tcpTimeoutBeforeDebug, func() {
		e.onOpenTimeout(flow)
	})
	mak.Set(&e.pendOpen, flow, &pendingOpenFlow{timer: timer})

	return filter.Accept
}

func (e *userspaceEngine) onOpenTimeout(flow flowtrack.Tuple) {
	e.mu.Lock()
	of, ok := e.pendOpen[flow]
	if !ok {
		// Not a tracked flow, or already handled & deleted.
		e.mu.Unlock()
		return
	}
	delete(e.pendOpen, flow)
	problem := of.problem
	e.mu.Unlock()

	if !problem.IsZero() {
		e.logf("open-conn-track: timeout opening %v; peer reported problem: %v", flow, problem)
	}

	// Diagnose why it might've timed out.
	pip, ok := e.PeerForIP(flow.DstAddr())
	if !ok {
		e.logf("open-conn-track: timeout opening %v; no associated peer node", flow)
		return
	}
	n := pip.Node
	if !n.IsWireGuardOnly() {
		if n.DiscoKey().IsZero() {
			e.logf("open-conn-track: timeout opening %v; peer node %v running pre-0.100", flow, n.Key().ShortString())
			return
		}
		if n.DERP() == "" {
			e.logf("open-conn-track: timeout opening %v; peer node %v not connected to any DERP relay", flow, n.Key().ShortString())
			return
		}
	}

	ps, found := e.getPeerStatusLite(n.Key())
	if !found {
		onlyZeroRoute := true // whether peerForIP returned n only because its /0 route matched
		for i := range n.AllowedIPs().Len() {
			r := n.AllowedIPs().At(i)
			if r.Bits() != 0 && r.Contains(flow.DstAddr()) {
				onlyZeroRoute = false
				break
			}
		}
		if onlyZeroRoute {
			// This node was returned by peerForIP because
			// its exit node /0 route(s) matched, but this
			// might not be the exit node that's currently
			// selected.  Rather than log misleading
			// errors, just don't log at all for now.
			// TODO(bradfitz): update this code to be
			// exit-node-aware and make peerForIP return
			// the node of the currently selected exit
			// node.
			return
		}
		e.logf("open-conn-track: timeout opening %v; target node %v in netmap but unknown to WireGuard", flow, n.Key().ShortString())
		return
	}

	// TODO(bradfitz): figure out what PeerStatus.LastHandshake
	// is. It appears to be the last time we sent a handshake,
	// which isn't what I expected. I thought it was when a
	// handshake completed, which is what I want.
	_ = ps.LastHandshake

	online := "?"
	if n.IsWireGuardOnly() {
		online = "wg"
	} else {
		if v := n.Online(); v != nil {
			if *v {
				online = "yes"
			} else {
				online = "no"
			}
		}
		if n.LastSeen() != nil && online != "yes" {
			online += fmt.Sprintf(", lastseen=%v", durFmt(*n.LastSeen()))
		}
	}
	e.logf("open-conn-track: timeout opening %v to node %v; online=%v, lastRecv=%v",
		flow, n.Key().ShortString(),
		online,
		e.magicConn.LastRecvActivityOfNodeKey(n.Key()))
}

func durFmt(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t).Round(time.Second)
	if d < 10*time.Minute {
		// node.LastSeen times are rounded very coarsely, and
		// we compare times from different clocks (server vs
		// local), so negative is common when close. Format as
		// "recent" if negative or actually recent.
		return "recent"
	}
	return d.String()
}
