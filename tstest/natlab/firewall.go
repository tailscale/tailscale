// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package natlab

import (
	"sync"
	"time"

	"inet.af/netaddr"
)

type session struct {
	src netaddr.IPPort
	dst netaddr.IPPort
}

type Firewall struct {
	// TrustedInterface is the interface that's allowed to send
	// anywhere. All other interfaces can only respond to traffic from
	// TrustedInterface.
	TrustedInterface *Interface
	// SessionTimeout is the lifetime of idle sessions in the firewall
	// state. Packets transiting from the TrustedInterface reset the
	// session lifetime to SessionTimeout.
	SessionTimeout time.Duration
	// TimeNow is a function returning the current time. If nil,
	// time.Now is used.
	TimeNow func() time.Time

	// TODO: tuple-ness pickiness: EIF, ADF, APDF
	// TODO: refresh directionality: outbound-only, both

	mu   sync.Mutex
	seen map[session]time.Time // session -> deadline
}

func (f *Firewall) timeNow() time.Time {
	if f.TimeNow != nil {
		return f.TimeNow()
	}
	return time.Now()
}

func (f *Firewall) HandlePacket(p *Packet, inIf *Interface) PacketVerdict {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seen == nil {
		f.seen = map[session]time.Time{}
	}

	if inIf == f.TrustedInterface {
		sess := session{
			src: p.Src,
			dst: p.Dst,
		}
		f.seen[sess] = f.timeNow().Add(f.SessionTimeout)
		p.Trace("firewall out ok")
		return Continue
	} else {
		// reverse src and dst because the session table is from the
		// POV of outbound packets.
		sess := session{
			src: p.Dst,
			dst: p.Src,
		}
		now := f.timeNow()
		if now.After(f.seen[sess]) {
			p.Trace("firewall drop")
			return Drop
		}
		p.Trace("firewall in ok")
		return Continue
	}
}
