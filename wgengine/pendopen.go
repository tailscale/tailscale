// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"os"
	"strconv"
	"time"

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
}

func (e *userspaceEngine) trackOpenPreFilterIn(pp *packet.Parsed, t *tstun.TUN) (res filter.Response) {
	res = filter.Accept // always

	if pp.IPVersion == 0 ||
		pp.IPProto != packet.TCP ||
		pp.TCPFlags&(packet.TCPSyn|packet.TCPRst) == 0 {
		return
	}

	flow := flowtrack.Tuple{Dst: pp.Src, Src: pp.Dst} // src/dst reversed

	e.mu.Lock()
	defer e.mu.Unlock()
	of, ok := e.pendOpen[flow]
	if !ok {
		// Not a tracked flow.
		return
	}
	of.timer.Stop()
	delete(e.pendOpen, flow)

	if pp.TCPFlags&packet.TCPRst != 0 {
		// TODO(bradfitz): have peer send a IP proto 99 "why"
		// packet first with details and log that instead
		// (e.g. ACL prohibited, shields up, etc).
		e.logf("open-conn-track: flow %v got RST by peer", flow)
		return
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
	if _, ok := e.pendOpen[flow]; !ok {
		// Not a tracked flow, or already handled & deleted.
		e.mu.Unlock()
		return
	}
	delete(e.pendOpen, flow)
	e.mu.Unlock()

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

	var ps *PeerStatus
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
