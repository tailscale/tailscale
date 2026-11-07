// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"errors"
	"net/netip"

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
		p := KernelPeerPath{Key: de.publicKey}
		de.mu.Lock()
		udpAddr, derpAddr, _ := de.addrForSendLocked(now)
		de.mu.Unlock()
		// A DERP address alongside the UDP one means the UDP path isn't
		// trusted (yet), so magicsock sends to both.
		if udpAddr.isDirect() && !derpAddr.IsValid() {
			p.Direct = udpAddr.ap
		}
		paths = append(paths, p)
	})
	return paths
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
