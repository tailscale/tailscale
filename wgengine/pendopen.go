// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"os"
	"strconv"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/flowtrack"
	"tailscale.com/net/packet"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/tstun"
)

const tcpTimeoutBeforeDebug = 5 * time.Second

// debugConnectFailures reports whether the local node should track
// outgoing TCP connections and log which ones fail and why.
func debugConnectFailures() bool {
	s := os.Getenv("TS_DEBUG_CONNECT_FAILURES")
	if s == "" {
		return true
	}
	v, _ := strconv.ParseBool(s)
	return v
}

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

func (e *userspaceEngine) trackOpenPreFilterIn(pp *packet.Parsed, t *tstun.TUN) (res filter.Response) {
	res = filter.Accept // always

	if pp.IPProto == packet.TSMP {
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
		pp.IPProto != packet.TCP ||
		pp.TCPFlags&(packet.TCPSyn|packet.TCPRst) == 0 {
		return
	}

	// Either a SYN or a RST came back. Remove it in either case.

	f := flowtrack.Tuple{Dst: pp.Src, Src: pp.Dst} // src/dst reversed
	removed := e.removeFlow(f)
	if removed && pp.TCPFlags&packet.TCPRst != 0 {
		e.logf("open-conn-track: flow TCP %v got RST by peer", f)
	}
	return
}

func (e *userspaceEngine) trackOpenPostFilterOut(pp *packet.Parsed, t *tstun.TUN) (res filter.Response) {
	res = filter.Accept // always

	if pp.IPVersion == 0 ||
		pp.IPProto != packet.TCP ||
		pp.TCPFlags&packet.TCPSyn == 0 {
		return
	}

	flow := flowtrack.Tuple{Src: pp.Src, Dst: pp.Dst}
	timer := time.AfterFunc(tcpTimeoutBeforeDebug, func() {
		e.onOpenTimeout(flow)
	})

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pendOpen == nil {
		e.pendOpen = make(map[flowtrack.Tuple]*pendingOpenFlow)
	}
	if _, dup := e.pendOpen[flow]; dup {
		// Duplicates are expected when the OS retransmits. Ignore.
		return
	}
	e.pendOpen[flow] = &pendingOpenFlow{timer: timer}

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
	n, ok := e.magicConn.PeerForIP(flow.Dst.IP)
	if !ok {
		e.logf("open-conn-track: timeout opening %v; no associated peer node", flow)
		return
	}
	if n.DiscoKey.IsZero() {
		e.logf("open-conn-track: timeout opening %v; peer node %v running pre-0.100", flow, n.Key.ShortString())
		return
	}
	if n.DERP == "" {
		e.logf("open-conn-track: timeout opening %v; peer node %v not connected to any DERP relay", flow, n.Key.ShortString())
		return
	}
	var lastSeen time.Time
	if n.LastSeen != nil {
		lastSeen = *n.LastSeen
	}

	var ps *ipnstate.PeerStatusLite
	if st, err := e.getStatus(); err == nil {
		for _, v := range st.Peers {
			if v.NodeKey == n.Key {
				v := v // copy
				ps = &v
			}
		}
	} else {
		e.logf("open-conn-track: timeout opening %v to node %v; failed to get engine status: %v", flow, n.Key.ShortString(), err)
		return
	}
	if ps == nil {
		e.logf("open-conn-track: timeout opening %v; target node %v in netmap but unknown to wireguard", flow, n.Key.ShortString())
		return
	}

	// TODO(bradfitz): figure out what PeerStatus.LastHandshake
	// is. It appears to be the last time we sent a handshake,
	// which isn't what I expected. I thought it was when a
	// handshake completed, which is what I want.
	_ = ps.LastHandshake

	e.logf("open-conn-track: timeout opening %v to node %v; lastSeen=%v, lastRecv=%v",
		flow, n.Key.ShortString(),
		agoOrNever(lastSeen), agoOrNever(e.magicConn.LastRecvActivityOfDisco(n.DiscoKey)))
}

func agoOrNever(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return time.Since(t).Round(time.Second).String()
}
