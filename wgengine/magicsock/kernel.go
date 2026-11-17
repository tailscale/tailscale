// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"errors"
	"net/netip"
	"time"

	"tailscale.com/net/packet"
	"tailscale.com/net/sockopts"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
)

// This file has the parts of magicsock used by the kernel data plane mode
// (tswg; see https://github.com/tailscale/tailscale/issues/426), in which
// the tswg kernel module, not wireguard-go, does WireGuard: it shares
// magicsock's UDP sockets, consuming WireGuard packets from them and
// leaving disco and STUN for magicsock. magicsock still picks each peer's
// path; the engine's kernel data plane tells the kernel to use a peer's
// direct path when it's trusted, and otherwise to send to a loopback
// bridge that hands the packets to magicsock to send (over DERP, a peer
// relay, or both DERP and a candidate path while it's not yet trusted).
// See also Options.KernelWGRecv for the receive side.

// kernelSocketHookFunc is the type of the function registered with
// SetKernelSocketHook.
type kernelSocketHookFunc func(network string, fd uintptr) error

// SetKernelSocketHook registers fn to be called with the file descriptor
// of magicsock's first UDP socket for each network ("udp4" or "udp6"), now
// for the current sockets and again each time a socket is (re)bound, so
// that fn can share the socket with the tswg kernel module. The fd is only
// valid during the call. fn must not call back into the Conn.
func (c *Conn) SetKernelSocketHook(fn func(network string, fd uintptr) error) {
	f := kernelSocketHookFunc(fn)
	c.kernelSocketHook.Store(&f)
	for _, x := range []struct {
		ruc     *RebindingUDPConn
		network string
	}{{&c.pconn4, "udp4"}, {&c.pconn6, "udp6"}} {
		x.ruc.mu.Lock()
		c.runKernelSocketHookLocked(x.ruc, x.network)
		x.ruc.mu.Unlock()
	}
}

// runKernelSocketHookLocked calls the kernel socket hook, if any, with
// ruc's first socket. ruc.mu must be held.
func (c *Conn) runKernelSocketHookLocked(ruc *RebindingUDPConn, network string) {
	fn := c.kernelSocketHook.Load()
	if fn == nil || ruc.group.bound == 0 {
		return
	}
	err := sockopts.ControlEach(ruc.group.conns[:1], func(fd uintptr) error {
		return (*fn)(network, fd)
	})
	if err != nil {
		c.logf("magicsock: kernel socket hook for %s: %v", network, err)
	}
}

var errUnknownPeer = errors.New("magicsock: unknown peer")

// SendWireGuardFromKernel sends the WireGuard packet pkt, which the tswg
// kernel module produced for the peer with key k, the way magicsock would
// send a packet from wireguard-go: over the peer's current best path,
// DERP, a peer relay, or both DERP and a candidate path if the best path
// isn't trusted yet.
func (c *Conn) SendWireGuardFromKernel(k key.NodePublic, pkt []byte) error {
	c.mu.Lock()
	de, ok := c.peerMap.endpointForNodeKey(k)
	c.mu.Unlock()
	if !ok {
		return errUnknownPeer
	}
	// The UDP send path needs headroom for a Geneve header (for peer
	// relays), as wireguard-go provides.
	const offset = packet.GeneveFixedHeaderLength
	buf := make([]byte, offset+len(pkt))
	copy(buf[offset:], pkt)
	return de.send(0, [][]byte{buf}, offset)
}

// KernelPeerPath is a peer's path as the tswg kernel module should use it.
type KernelPeerPath struct {
	Key key.NodePublic

	// Direct is the peer's direct UDP address, if magicsock trusts its
	// best path and that path is direct (not DERP or a peer relay), so
	// that the kernel can send to it directly. Otherwise it's the zero
	// value, and the kernel should send to magicsock instead.
	Direct netip.AddrPort
}

// KernelPeerPaths returns the paths the tswg kernel module should use for
// all of magicsock's peers.
func (c *Conn) KernelPeerPaths() []KernelPeerPath {
	now := mono.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	paths := make([]KernelPeerPath, 0, c.peerMap.nodeCount())
	c.peerMap.forEachEndpoint(func(de *endpoint) {
		paths = append(paths, de.kernelPath(now))
	})
	return paths
}

// KernelPeerPath is like KernelPeerPaths, for the single peer with key k.
func (c *Conn) KernelPeerPath(k key.NodePublic) (_ KernelPeerPath, ok bool) {
	c.mu.Lock()
	de, ok := c.peerMap.endpointForNodeKey(k)
	c.mu.Unlock()
	if !ok {
		return KernelPeerPath{}, false
	}
	return de.kernelPath(mono.Now()), true
}

// kernelPath returns the path the tswg kernel module should use for de.
func (de *endpoint) kernelPath(now mono.Time) KernelPeerPath {
	de.mu.Lock()
	defer de.mu.Unlock()
	return KernelPeerPath{Key: de.publicKey, Direct: de.kernelDirectLocked(now)}
}

// kernelDirectLocked returns de's direct UDP address for the kernel to
// send to, if it has a trusted direct (not DERP or peer relay) best path,
// or else the zero value. de.mu must be held.
func (de *endpoint) kernelDirectLocked(now mono.Time) netip.AddrPort {
	if de.isWireguardOnly {
		// WireGuard-only peers (no disco) have no trust window; use
		// whichever of their addresses magicsock would send to.
		if udpAddr, _, _ := de.addrForSendLocked(now); udpAddr.isDirect() {
			return udpAddr.ap
		}
		return netip.AddrPort{}
	}
	if de.bestAddr.isDirect() && now.Before(de.trustBestAddrUntil) {
		return de.bestAddr.ap
	}
	return netip.AddrPort{}
}

// SetKernelPathHook registers fn to be called, from its own goroutine, with
// a peer's key whenever the result of KernelPeerPath for that peer may have
// changed: its best path changed, or became trusted, or stopped being
// trusted, or the peer was added or removed. It lets the kernel data plane
// switch the kernel's endpoint for the peer right away, without polling,
// and sync just that peer.
func (c *Conn) SetKernelPathHook(fn func(key.NodePublic)) {
	c.kernelPathHook.Store(&fn)
}

// noteKernelPeerSetChange calls the kernel path hook, if any, for de, which
// was just added to or removed from the peer map.
func (de *endpoint) noteKernelPeerSetChange() {
	if de.c == nil {
		return // in tests
	}
	if fn := de.c.kernelPathHook.Load(); fn != nil {
		go (*fn)(de.publicKey)
	}
}

// noteKernelPathLocked calls the kernel path hook, if any, if de's kernel
// path changed since it last did. While de's kernel path is direct, it
// keeps a timer armed for when that path's trust expires, since nothing
// else happens then. de.mu must be held.
func (de *endpoint) noteKernelPathLocked() {
	if de.c == nil {
		return // in tests
	}
	fn := de.c.kernelPathHook.Load()
	if fn == nil {
		return
	}
	now := mono.Now()
	direct := de.kernelDirectLocked(now)
	if direct != de.kernelDirect {
		de.kernelDirect = direct
		go (*fn)(de.publicKey)
	}
	if direct.IsValid() && !de.isWireguardOnly && de.kernelTrustTimer == nil {
		de.kernelTrustTimer = time.AfterFunc(de.trustBestAddrUntil.Sub(now), de.kernelTrustTimerFired)
	}
}

// kernelTrustTimerFired re-checks de's kernel path when its trust may have
// expired, re-arming the timer if trust was extended meanwhile.
func (de *endpoint) kernelTrustTimerFired() {
	de.mu.Lock()
	defer de.mu.Unlock()
	de.kernelTrustTimer = nil
	de.noteKernelPathLocked()
}

// NoteKernelActivity tells magicsock that the tswg kernel module sent (tx)
// or received (rx) WireGuard packets for the peer with key k on its own,
// over a direct path, without going through magicsock. magicsock uses
// that, as it would for packets from wireguard-go, to keep the session's
// disco heartbeats going, which keep the direct path trusted.
func (c *Conn) NoteKernelActivity(k key.NodePublic, tx, rx bool) {
	c.mu.Lock()
	de, ok := c.peerMap.endpointForNodeKey(k)
	c.mu.Unlock()
	if !ok {
		return
	}
	now := mono.Now()
	if rx {
		de.lastRecvUDPAny.StoreAtomic(now)
	}
	if !tx {
		return
	}
	de.mu.Lock()
	defer de.mu.Unlock()
	udpAddr, _, _ := de.addrForSendLocked(now)
	if !udpAddr.isDirect() || now.After(de.trustBestAddrUntil) {
		de.sendDiscoPingsLocked(now, true)
	}
	de.noteTxActivityExtTriggerLocked(now)
	de.lastSendAny = now
}
