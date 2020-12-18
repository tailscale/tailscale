// Copyright (c) 2019 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magicsock

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/wgcfg"
	"inet.af/netaddr"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func shouldSprayPacket(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	msgType := binary.LittleEndian.Uint32(b[:4])
	switch msgType {
	case device.MessageInitiationType,
		device.MessageResponseType,
		device.MessageCookieReplyType: // TODO: necessary?
		return true
	}
	return false
}

const sprayPeriod = 3 * time.Second

// appendDests appends to dsts the destinations that b should be
// written to in order to reach as. Some of the returned IPPorts may
// be fake addrs representing DERP servers.
//
// It also returns as's current roamAddr, if any.
func (as *AddrSet) appendDests(dsts []netaddr.IPPort, b []byte) (_ []netaddr.IPPort, roamAddr netaddr.IPPort) {
	spray := shouldSprayPacket(b) // true for handshakes
	now := as.timeNow()

	as.mu.Lock()
	defer as.mu.Unlock()

	as.lastSend = now

	// Some internal invariant checks.
	if len(as.addrs) != len(as.ipPorts) {
		panic(fmt.Sprintf("lena %d != leni %d", len(as.addrs), len(as.ipPorts)))
	}
	if n1, n2 := as.roamAddr != nil, as.roamAddrStd != nil; n1 != n2 {
		panic(fmt.Sprintf("roamnil %v != roamstdnil %v", n1, n2))
	}

	// Spray logic.
	//
	// After exchanging a handshake with a peer, we send some outbound
	// packets to every endpoint of that peer. These packets are spaced out
	// over several seconds to make sure that our peer has an opportunity to
	// send its own spray packet to us before we are done spraying.
	//
	// Multiple packets are necessary because we have to both establish the
	// NAT mappings between two peers *and use* the mappings to switch away
	// from DERP to a higher-priority UDP endpoint.
	const sprayFreq = 250 * time.Millisecond
	if spray {
		as.lastSpray = now
		as.stopSpray = now.Add(sprayPeriod)

		// Reset our favorite route on new handshakes so we
		// can downgrade to a worse path if our better path
		// goes away. (https://github.com/tailscale/tailscale/issues/92)
		as.curAddr = -1
	} else if now.Before(as.stopSpray) {
		// We are in the spray window. If it has been sprayFreq since we
		// last sprayed a packet, spray this packet.
		if now.Sub(as.lastSpray) >= sprayFreq {
			spray = true
			as.lastSpray = now
		}
	}

	// Pick our destination address(es).
	switch {
	case spray:
		// This packet is being sprayed to all addresses.
		for i := range as.ipPorts {
			dsts = append(dsts, as.ipPorts[i])
		}
		if as.roamAddr != nil {
			dsts = append(dsts, *as.roamAddr)
		}
	case as.roamAddr != nil:
		// We have a roaming address, prefer it over other addrs.
		// TODO(danderson): this is not correct, there's no reason
		// roamAddr should be special like this.
		dsts = append(dsts, *as.roamAddr)
	case as.curAddr != -1:
		if as.curAddr >= len(as.addrs) {
			as.Logf("[unexpected] magicsock bug: as.curAddr >= len(as.addrs): %d >= %d", as.curAddr, len(as.addrs))
			break
		}
		// No roaming addr, but we've seen packets from a known peer
		// addr, so keep using that one.
		dsts = append(dsts, as.ipPorts[as.curAddr])
	default:
		// We know nothing about how to reach this peer, and we're not
		// spraying. Use the first address in the array, which will
		// usually be a DERP address that guarantees connectivity.
		if len(as.ipPorts) > 0 {
			dsts = append(dsts, as.ipPorts[0])
		}
	}

	if logPacketDests {
		as.Logf("spray=%v; roam=%v; dests=%v", spray, as.roamAddr, dsts)
	}
	if as.roamAddr != nil {
		roamAddr = *as.roamAddr
	}
	return dsts, roamAddr
}

// AddrSet is a set of UDP addresses that implements wireguard/conn.Endpoint.
//
// This is the legacy endpoint for peers that don't support discovery;
// it predates discoEndpoint.
type AddrSet struct {
	publicKey key.Public // peer public key used for DERP communication

	// addrs is an ordered priority list provided by wgengine,
	// sorted from expensive+slow+reliable at the begnining to
	// fast+cheap at the end. More concretely, it's typically:
	//
	//     [DERP fakeip:node, Global IP:port, LAN ip:port]
	//
	// But there could be multiple or none of each.
	addrs   []net.UDPAddr
	ipPorts []netaddr.IPPort // same as addrs, in different form

	// clock, if non-nil, is used in tests instead of time.Now.
	clock func() time.Time
	Logf  logger.Logf // must not be nil

	mu sync.Mutex // guards following fields

	lastSend time.Time

	// roamAddr is non-nil if/when we receive a correctly signed
	// WireGuard packet from an unexpected address. If so, we
	// remember it and send responses there in the future, but
	// this should hopefully never be used (or at least used
	// rarely) in the case that all the components of Tailscale
	// are correctly learning/sharing the network map details.
	roamAddr    *netaddr.IPPort
	roamAddrStd *net.UDPAddr

	// curAddr is an index into addrs of the highest-priority
	// address a valid packet has been received from so far.
	// If no valid packet from addrs has been received, curAddr is -1.
	curAddr int

	// stopSpray is the time after which we stop spraying packets.
	stopSpray time.Time

	// lastSpray is the last time we sprayed a packet.
	lastSpray time.Time

	// loggedLogPriMask is a bit field of that tracks whether
	// we've already logged about receiving a packet from a low
	// priority ("low-pri") address when we already have curAddr
	// set to a better one. This is only to suppress some
	// redundant logs.
	loggedLogPriMask uint32
}

// derpID returns this AddrSet's home DERP node, or 0 if none is found.
func (as *AddrSet) derpID() int {
	for _, ua := range as.addrs {
		if ua.IP.Equal(derpMagicIP) {
			return ua.Port
		}
	}
	return 0
}

func (as *AddrSet) timeNow() time.Time {
	if as.clock != nil {
		return as.clock()
	}
	return time.Now()
}

var noAddr, _ = netaddr.FromStdAddr(net.ParseIP("127.127.127.127"), 127, "")

func (a *AddrSet) dst() netaddr.IPPort {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.roamAddr != nil {
		return *a.roamAddr
	}
	if len(a.addrs) == 0 {
		return noAddr
	}
	i := a.curAddr
	if i == -1 {
		i = 0
	}
	return a.ipPorts[i]
}

// packUDPAddr packs a UDPAddr in the form wanted by WireGuard.
func packUDPAddr(ua *net.UDPAddr) []byte {
	ip := ua.IP.To4()
	if ip == nil {
		ip = ua.IP
	}
	b := make([]byte, 0, len(ip)+2)
	b = append(b, ip...)
	b = append(b, byte(ua.Port))
	b = append(b, byte(ua.Port>>8))
	return b
}

func (a *AddrSet) DstToBytes() []byte {
	return packIPPort(a.dst())
}
func (a *AddrSet) DstToString() string {
	dst := a.dst()
	return dst.String()
}
func (a *AddrSet) DstIP() net.IP {
	return a.dst().IP.IPAddr().IP // TODO: add netaddr accessor to cut an alloc here?
}
func (a *AddrSet) SrcIP() net.IP       { return nil }
func (a *AddrSet) SrcToString() string { return "" }
func (a *AddrSet) ClearSrc()           {}

func (a *AddrSet) UpdateDst(new *net.UDPAddr) error {
	if new.IP.Equal(derpMagicIP) {
		// Never consider DERP addresses as a viable candidate for
		// either curAddr or roamAddr. It's only ever a last resort
		// choice, never a preferred choice.
		// This is a hot path for established connections.
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.roamAddrStd != nil && equalUDPAddr(new, a.roamAddrStd) {
		// Packet from the current roaming address, no logging.
		// This is a hot path for established connections.
		return nil
	}
	if a.roamAddr == nil && a.curAddr >= 0 && equalUDPAddr(new, &a.addrs[a.curAddr]) {
		// Packet from current-priority address, no logging.
		// This is a hot path for established connections.
		return nil
	}

	newa, ok := netaddr.FromStdAddr(new.IP, new.Port, new.Zone)
	if !ok {
		return nil
	}

	index := -1
	for i := range a.addrs {
		if equalUDPAddr(new, &a.addrs[i]) {
			index = i
			break
		}
	}

	publicKey := wgcfg.Key(a.publicKey)
	pk := publicKey.ShortString()
	old := "<none>"
	if a.curAddr >= 0 {
		old = a.addrs[a.curAddr].String()
	}

	switch {
	case index == -1:
		if a.roamAddr == nil {
			a.Logf("magicsock: rx %s from roaming address %s, set as new priority", pk, new)
		} else {
			a.Logf("magicsock: rx %s from roaming address %s, replaces roaming address %s", pk, new, a.roamAddr)
		}
		a.roamAddr = &newa
		a.roamAddrStd = new

	case a.roamAddr != nil:
		a.Logf("magicsock: rx %s from known %s (%d), replaces roaming address %s", pk, new, index, a.roamAddr)
		a.roamAddr = nil
		a.roamAddrStd = nil
		a.curAddr = index
		a.loggedLogPriMask = 0

	case a.curAddr == -1:
		a.Logf("magicsock: rx %s from %s (%d/%d), set as new priority", pk, new, index, len(a.addrs))
		a.curAddr = index
		a.loggedLogPriMask = 0

	case index < a.curAddr:
		if 1 <= index && index <= 32 && (a.loggedLogPriMask&1<<(index-1)) == 0 {
			a.Logf("magicsock: rx %s from low-pri %s (%d), keeping current %s (%d)", pk, new, index, old, a.curAddr)
			a.loggedLogPriMask |= 1 << (index - 1)
		}

	default: // index > a.curAddr
		a.Logf("magicsock: rx %s from %s (%d/%d), replaces old priority %s", pk, new, index, len(a.addrs), old)
		a.curAddr = index
		a.loggedLogPriMask = 0
	}

	return nil
}

func equalUDPAddr(x, y *net.UDPAddr) bool {
	return x.Port == y.Port && x.IP.Equal(y.IP)
}

func (a *AddrSet) String() string {
	a.mu.Lock()
	defer a.mu.Unlock()

	buf := new(strings.Builder)
	buf.WriteByte('[')
	if a.roamAddr != nil {
		buf.WriteString("roam:")
		sbPrintAddr(buf, *a.roamAddrStd)
	}
	for i, addr := range a.addrs {
		if i > 0 || a.roamAddr != nil {
			buf.WriteString(", ")
		}
		sbPrintAddr(buf, addr)
		if a.curAddr == i {
			buf.WriteByte('*')
		}
	}
	buf.WriteByte(']')

	return buf.String()
}

func (as *AddrSet) populatePeerStatus(ps *ipnstate.PeerStatus) {
	as.mu.Lock()
	defer as.mu.Unlock()

	ps.LastWrite = as.lastSend
	for i, ua := range as.addrs {
		if ua.IP.Equal(derpMagicIP) {
			continue
		}
		uaStr := ua.String()
		ps.Addrs = append(ps.Addrs, uaStr)
		if as.curAddr == i {
			ps.CurAddr = uaStr
		}
	}
	if as.roamAddr != nil {
		ps.CurAddr = udpAddrDebugString(*as.roamAddrStd)
	}
}

func (a *AddrSet) Addrs() []wgcfg.Endpoint {
	var eps []wgcfg.Endpoint
	for _, addr := range a.addrs {
		eps = append(eps, wgcfg.Endpoint{
			Host: addr.IP.String(),
			Port: uint16(addr.Port),
		})
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.roamAddr != nil {
		eps = append(eps, wgcfg.Endpoint{
			Host: a.roamAddr.IP.String(),
			Port: uint16(a.roamAddr.Port),
		})
	}
	return eps
}

// singleEndpoint is a wireguard-go/conn.Endpoint used for "roaming
// addressed" in releases of Tailscale that predate discovery
// messages. New peers use discoEndpoint.
type singleEndpoint net.UDPAddr

func (e *singleEndpoint) ClearSrc()           {}
func (e *singleEndpoint) DstIP() net.IP       { return (*net.UDPAddr)(e).IP }
func (e *singleEndpoint) SrcIP() net.IP       { return nil }
func (e *singleEndpoint) SrcToString() string { return "" }
func (e *singleEndpoint) DstToString() string { return (*net.UDPAddr)(e).String() }
func (e *singleEndpoint) DstToBytes() []byte  { return packUDPAddr((*net.UDPAddr)(e)) }
func (e *singleEndpoint) UpdateDst(dst *net.UDPAddr) error {
	return fmt.Errorf("magicsock.singleEndpoint(%s).UpdateDst(%s): should never be called", (*net.UDPAddr)(e), dst)
}
func (e *singleEndpoint) Addrs() []wgcfg.Endpoint {
	return []wgcfg.Endpoint{{
		Host: e.IP.String(),
		Port: uint16(e.Port),
	}}
}
