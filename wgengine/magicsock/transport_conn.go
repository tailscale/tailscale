// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/disco"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
)

// This file implements [TransportHost] (via *Conn and the per-transport
// transportHost binding) and [TransportPeer] (via *endpoint), plus the
// magicsock-side send and receive plumbing shared by all pluggable transports.
// It deals only in magicsock types; each transport's own implementation lives
// in its package.

// transportMagicPort is the fixed port used in the synthetic [epAddr] that
// represents a transport path. The magic IP identifies which transport; the
// port is arbitrary but stable.
const transportMagicPort = 12345

// The following methods implement the transport-independent parts of
// [TransportHost] on *Conn. The transport-specific parts (which need to know
// which transport is calling) are implemented on *transportHost below and
// delegate here with an explicit index.

// LocalDiscoKey implements [TransportHost].
func (c *Conn) LocalDiscoKey() key.DiscoPublic { return c.DiscoPublicKey() }

// Disabled implements [TransportHost]. Pluggable transports are suppressed when
// the operator has forced all traffic over DERP, or disabled pluggable
// transports, for debugging. In either case affected peers fall back to DERP.
func (c *Conn) Disabled() bool { return debugAlwaysDERP() || debugDisablePluggableTransports() }

// Logf implements [TransportHost].
func (c *Conn) Logf(format string, args ...any) { c.logf(format, args...) }

// PeerForDisco implements [TransportHost].
func (c *Conn) PeerForDisco(dk key.DiscoPublic) (TransportPeer, bool) {
	if ep := c.findEndpointByDisco(dk); ep != nil {
		return ep, true
	}
	return nil, false
}

// sendTransportSignal routes a transport signaling disco message to the peer
// identified by dst, via that peer's home DERP region, tagged with the given
// transport name so the receiver can dispatch it.
func (c *Conn) sendTransportSignal(name string, dst key.DiscoPublic, payload []byte) error {
	// Find the endpoint and its home DERP address under the Conn lock.
	c.mu.Lock()
	var (
		derpAddr netip.AddrPort
		nodeKey  key.NodePublic
		found    bool
	)
	c.peerMap.forEachEndpointWithDiscoKey(dst, func(ep *endpoint) bool {
		ep.mu.Lock()
		derpAddr = ep.derpAddr
		ep.mu.Unlock()
		nodeKey = ep.publicKey
		found = true
		return false // stop after first match
	})
	c.mu.Unlock()

	if !found {
		return fmt.Errorf("transport: no endpoint for disco key %v", dst.ShortString())
	}
	if !derpAddr.IsValid() {
		return fmt.Errorf("transport: no DERP address for peer %v", dst.ShortString())
	}

	m := &disco.TransportSignal{Transport: name, Payload: payload}
	_, err := c.sendDiscoMessage(epAddr{ap: derpAddr}, nodeKey, dst, m, discoLog)
	return err
}

// deliverTransportPacket queues a decrypted transport data packet for processing
// by wireguard-go through transportRecvCh, tagged with the transport index so
// the receive path can attribute it to the right magic IP.
func (c *Conn) deliverTransportPacket(idx int, b []byte, src key.NodePublic) {
	// Copy into a fresh slice: b belongs to the reader goroutine's reusable
	// buffer which will be overwritten on the next Read call.
	pkt := make([]byte, len(b))
	copy(pkt, b)

	select {
	case c.transportRecvCh <- transportReadResult{transportIdx: idx, n: len(pkt), src: src, buf: pkt}:
	case <-c.connCtx.Done():
	default:
		c.logf("transport: dropped packet from %v, receive channel full", src.ShortString())
	}
}

// The following methods implement [TransportHost] on *transportHost, the
// per-transport binding. They forward to *Conn with this transport's identity.

func (h *transportHost) LocalDiscoKey() key.DiscoPublic { return h.c.LocalDiscoKey() }
func (h *transportHost) Disabled() bool                 { return h.c.Disabled() }
func (h *transportHost) Logf(format string, args ...any) {
	h.c.Logf(format, args...)
}

func (h *transportHost) PeerForDisco(dk key.DiscoPublic) (TransportPeer, bool) {
	return h.c.PeerForDisco(dk)
}

// SendSignal implements [TransportHost]. It tags the payload with this
// transport's registered name.
func (h *transportHost) SendSignal(dst key.DiscoPublic, payload []byte) error {
	return h.c.sendTransportSignal(registeredTransports[h.idx].name, dst, payload)
}

// DeliverPacket implements [TransportHost]. It attributes the packet to this
// transport.
func (h *transportHost) DeliverPacket(b []byte, src key.NodePublic) {
	h.c.deliverTransportPacket(h.idx, b, src)
}

// SetChannelReady implements [TransportHost]. It marks this transport's channel
// to peer open (ready=true) or closed (ready=false). While ready, the disco
// heartbeat re-probes this transport's magic address every interval (see
// maybeProbeTransportsLocked), so its path can be selected, and re-selected
// after any fallback, purely on disco pong evidence. This is the analogue of
// relay path re-discovery: a one-shot promotion would wedge on DERP the first
// time a pong arrived late.
func (h *transportHost) SetChannelReady(peer TransportPeer, ready bool) {
	ep, ok := peer.(*endpoint)
	if !ok {
		return
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.setTransportChannelReadyLocked(h.idx, ready)
	if ready {
		// Send an immediate probe so promotion doesn't wait up to a full
		// heartbeat interval.
		ep.maybeProbeTransportsLocked(mono.Now())
	}
}

// The following methods implement [TransportPeer] on *endpoint.

// DiscoKey implements [TransportPeer].
func (de *endpoint) DiscoKey() (key.DiscoPublic, bool) {
	d := de.disco.Load()
	if d == nil {
		return key.DiscoPublic{}, false
	}
	return d.key(), true
}

// NodeKey implements [TransportPeer].
func (de *endpoint) NodeKey() key.NodePublic { return de.publicKey }

// NodeAddr implements [TransportPeer].
func (de *endpoint) NodeAddr() netip.Addr { return de.nodeAddr }

// IsJS implements [TransportPeer]. It reports whether the peer's last-known
// Hostinfo OS is "js", i.e. the peer is a browser/Wasm node (a node whose
// runtime.GOOS is "js").
func (de *endpoint) IsJS() bool {
	de.c.mu.Lock()
	defer de.c.mu.Unlock()
	nv, ok := de.c.peersByID[de.nodeID]
	if !ok || !nv.Valid() {
		return false
	}
	hi := nv.Hostinfo()
	return hi.Valid() && hi.OS() == "js"
}

// DERPReady implements [TransportPeer].
func (de *endpoint) DERPReady() bool {
	de.mu.Lock()
	defer de.mu.Unlock()
	return de.derpAddr.IsValid()
}

// sendTransportBatch packs all buffs into a single message and sends it over the
// transport at index idx. Batching is the critical throughput optimization: a
// per-packet transport path typically produces one lower-layer send per
// WireGuard packet. Packing N packets into one message reduces that to a single
// write, the same advantage sendUDPBatch (sendmmsg) gives the regular UDP path.
//
// Wire format for N>1: [TransportBatchMagic][2-byte BE len][packet]...
// Single packet: sent as-is with no framing overhead.
func (c *Conn) sendTransportBatch(idx int, pubKey key.NodePublic, buffs [][]byte, offset int) error {
	inst, ok := c.transports[idx]
	if !ok {
		return nil
	}
	t := inst.t

	// Resolve endpoint and disco key once for the whole batch.
	c.mu.Lock()
	ep, ok := c.peerMap.endpointForNodeKey(pubKey)
	c.mu.Unlock()
	if !ok || ep == nil {
		return nil
	}
	disco := ep.disco.Load()
	if disco == nil {
		return nil
	}

	if len(buffs) == 1 {
		// Fast path: single packet, no framing overhead.
		b := buffs[0][offset:]
		if err := t.SendPacket(disco.key(), b); err != nil {
			return err
		}
		c.metrics.outboundPacketsTransportTotal.Add(1)
		c.metrics.outboundBytesTransportTotal.Add(int64(len(b)))
		return nil
	}

	// Multi-packet batch path.
	size := 1 // magic byte
	for _, b := range buffs {
		size += 2 + len(b[offset:])
	}
	batch := make([]byte, size)
	batch[0] = TransportBatchMagic
	pos := 1
	var totalBytes int64
	for _, b := range buffs {
		pkt := b[offset:]
		binary.BigEndian.PutUint16(batch[pos:], uint16(len(pkt)))
		pos += 2
		copy(batch[pos:], pkt)
		pos += len(pkt)
		totalBytes += int64(len(pkt))
	}
	if err := t.SendPacket(disco.key(), batch); err != nil {
		return err
	}
	c.metrics.outboundPacketsTransportTotal.Add(int64(len(buffs)))
	c.metrics.outboundBytesTransportTotal.Add(totalBytes)
	return nil
}

// sendTransport sends a single packet over the transport at index idx to pubKey.
func (c *Conn) sendTransport(idx int, addr netip.AddrPort, pubKey key.NodePublic, b []byte) (sent bool, err error) {
	inst, ok := c.transports[idx]
	if !ok {
		return false, nil
	}
	t := inst.t

	c.mu.Lock()
	ep, ok := c.peerMap.endpointForNodeKey(pubKey)
	c.mu.Unlock()
	if !ok {
		return false, nil
	}

	disco := ep.disco.Load()
	if disco == nil {
		return false, nil
	}

	if err := t.SendPacket(disco.key(), b); err != nil {
		return false, err
	}

	c.metrics.outboundPacketsTransportTotal.Add(1)
	c.metrics.outboundBytesTransportTotal.Add(int64(len(b)))

	return true, nil
}

// receiveTransport is the [conn.ReceiveFunc] for all pluggable transports. It
// reads packets queued by [Conn.deliverTransportPacket] from transportRecvCh,
// blocking until one carrying WireGuard data is available, and returns that
// single packet.
func (c *connBind) receiveTransport(slab []byte, packets []conn.ReceivedPacket) (int, error) {
	// Mirror receiveDERP: block for messages and keep waiting when a message
	// yields no WireGuard data (n == 0, e.g. a disco packet handled inline).
	// A ReceiveFunc must never return (0, nil): wireguard-go treats that as a
	// spurious wake and it stops delivering, which manifests as one packet
	// getting through and then a stall.
	for wr := range c.transportRecvCh {
		if c.isClosed() {
			break
		}
		n, ep := c.processTransportReadResult(wr, slab)
		if n == 0 {
			// No WireGuard data (disco packet, unknown peer, etc.). Wait for
			// the next one.
			continue
		}
		packets[0].Size = n
		packets[0].Offset = 0
		packets[0].Endpoint = ep
		return 1, nil
	}
	return 0, net.ErrClosed
}

// processTransportReadResult processes a transport packet received from
// transportRecvCh. It's similar to processDERPReadResult but for pluggable
// transports, and tags the synthetic source address with the transport's magic
// IP so path selection attributes it correctly.
func (c *Conn) processTransportReadResult(wr transportReadResult, b []byte) (n int, ep *endpoint) {
	if wr.buf == nil {
		return 0, nil
	}
	inst, ok := c.transports[wr.transportIdx]
	if !ok {
		return 0, nil
	}
	magicIP := inst.magicIP

	n = wr.n
	ncopy := copy(b, wr.buf[:n])
	if ncopy != n {
		err := fmt.Errorf("received transport packet of length %d that's too big for WireGuard buf size %d", n, ncopy)
		c.logf("magicsock: %v", err)
		return 0, nil
	}

	srcAddr := epAddr{ap: netip.AddrPortFrom(magicIP, transportMagicPort)}

	// Check if this looks like a disco packet.
	pt, isGeneveEncap := packetLooksLike(b[:n])
	if pt == packetLooksLikeDisco && !isGeneveEncap {
		c.handleDiscoMessage(b[:n], srcAddr, false, wr.src, discoRXPathTransport)
		return 0, nil
	}

	// Find the endpoint by node key.
	c.mu.Lock()
	ep, ok = c.peerMap.endpointForNodeKey(wr.src)
	c.mu.Unlock()

	if !ok {
		// We don't know anything about this node key.
		return 0, nil
	}

	ep.noteRecvActivity(srcAddr, mono.Now())
	if update := c.connCounter.Load(); update != nil {
		update(0, netip.AddrPortFrom(ep.nodeAddr, 0), srcAddr.ap, 1, n, true)
	}

	c.metrics.inboundPacketsTransportTotal.Add(1)
	c.metrics.inboundBytesTransportTotal.Add(int64(n))

	return n, ep
}

// transportRemoteAddrForDisco returns the selected remote address for the
// transport serving the given magic IP and disco key, or "" if unavailable. It
// is used by populatePeerStatus for display.
func (c *Conn) transportRemoteAddrForDisco(magicIP netip.Addr, dk key.DiscoPublic) string {
	inst, ok := c.transportByMagicIP(magicIP)
	if !ok {
		return ""
	}
	return inst.t.GetRemoteAddr(dk)
}
