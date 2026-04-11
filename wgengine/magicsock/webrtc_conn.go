// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/disco"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
)

// This file implements [WebRTCBackend] on *Conn and the magicsock-side send
// and receive plumbing for the WebRTC path. The pion-using logic lives in
// feature/webrtc; everything here deals only in magicsock types.

// webrtcMagicPort is the fixed port used in the synthetic [epAddr] that
// represents a WebRTC path. The magic IP identifies the path as WebRTC; the
// port is arbitrary but stable.
const webrtcMagicPort = 12345

// LocalDiscoKey implements [WebRTCBackend].
func (c *Conn) LocalDiscoKey() key.DiscoPublic { return c.DiscoPublicKey() }

// DisableWebRTC implements [WebRTCBackend]. WebRTC is suppressed when the
// operator has forced all traffic over DERP for debugging.
func (c *Conn) DisableWebRTC() bool { return debugAlwaysDERP() }

// Logf implements [WebRTCBackend].
func (c *Conn) Logf(format string, args ...any) { c.logf(format, args...) }

// PeerForDisco implements [WebRTCBackend].
func (c *Conn) PeerForDisco(dk key.DiscoPublic) (WebRTCPeer, bool) {
	if ep := c.findEndpointByDisco(dk); ep != nil {
		return ep, true
	}
	return nil, false
}

// SendSignal implements [WebRTCBackend]. It routes a WebRTC signaling disco
// message to the peer identified by dst, via that peer's home DERP region.
func (c *Conn) SendSignal(dst key.DiscoPublic, m disco.Message) error {
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
		return fmt.Errorf("webrtc: no endpoint for disco key %v", dst.ShortString())
	}
	if !derpAddr.IsValid() {
		return fmt.Errorf("webrtc: no DERP address for peer %v", dst.ShortString())
	}

	_, err := c.sendDiscoMessage(epAddr{ap: derpAddr}, nodeKey, dst, m, discoLog)
	return err
}

// DeliverPacket implements [WebRTCBackend]. It queues a decrypted WebRTC
// data-channel packet for processing by wireguard-go through webrtcRecvCh.
func (c *Conn) DeliverPacket(b []byte, src key.NodePublic) {
	// Copy into a fresh slice: b belongs to the reader goroutine's reusable
	// buffer which will be overwritten on the next Read call.
	pkt := make([]byte, len(b))
	copy(pkt, b)

	select {
	case c.webrtcRecvCh <- webrtcReadResult{n: len(pkt), src: src, buf: pkt}:
	case <-c.connCtx.Done():
	default:
		c.logf("webrtc: dropped packet from %v, receive channel full", src.ShortString())
	}
}

// The following methods implement [WebRTCPeer] on *endpoint.

// DiscoKey implements [WebRTCPeer].
func (de *endpoint) DiscoKey() (key.DiscoPublic, bool) {
	d := de.disco.Load()
	if d == nil {
		return key.DiscoPublic{}, false
	}
	return d.key(), true
}

// NodeKey implements [WebRTCPeer].
func (de *endpoint) NodeKey() key.NodePublic { return de.publicKey }

// NodeAddr implements [WebRTCPeer].
func (de *endpoint) NodeAddr() netip.Addr { return de.nodeAddr }

// IsJS implements [WebRTCPeer]. It reports whether the peer's last-known
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

// DERPReady implements [WebRTCPeer].
func (de *endpoint) DERPReady() bool {
	de.mu.Lock()
	defer de.mu.Unlock()
	return de.derpAddr.IsValid()
}

// SetWebRTCPath implements [WebRTCPeer]. It promotes the WebRTC magic address
// to the endpoint's best path if it beats the current best path.
func (de *endpoint) SetWebRTCPath() {
	de.mu.Lock()
	defer de.mu.Unlock()

	// The magic IP identifies this as WebRTC, not UDP. Latency starts at zero
	// and is refined by disco pings, same as DERP.
	webrtcAddr := addrQuality{
		epAddr: epAddr{
			ap: netip.AddrPortFrom(tailcfg.WebRTCMagicIPAddr, webrtcMagicPort),
		},
	}
	now := mono.Now()
	if betterAddr(webrtcAddr, de.bestAddr) {
		de.bestAddr = webrtcAddr
		de.bestAddrAt = now
		de.trustBestAddrUntil = now.Add(5 * time.Minute)
	}
}

// ClearWebRTCPath implements [WebRTCPeer]. If the endpoint's best path is
// currently the WebRTC magic address, it resets it so traffic falls back to
// DERP.
func (de *endpoint) ClearWebRTCPath() {
	de.mu.Lock()
	defer de.mu.Unlock()
	if de.bestAddr.ap.Addr() == tailcfg.WebRTCMagicIPAddr {
		de.bestAddr = addrQuality{}
		de.trustBestAddrUntil = 0
	}
}

// sendWebRTCBatch packs all buffs into a single SCTP message and sends it.
// Batching is the critical throughput optimization: the per-packet WebRTC
// path calls rwc.Write once per WireGuard packet, producing one SCTP message,
// one DTLS record, and one UDP send per packet. Packing N packets into one
// SCTP message reduces that to a single write, the same advantage
// sendUDPBatch (sendmmsg) gives the regular UDP path.
//
// Wire format for N>1: [0xBA magic][2-byte BE len][packet]...[2-byte BE len][packet]
// Single packet: sent as-is with no framing overhead.
func (c *Conn) sendWebRTCBatch(pubKey key.NodePublic, buffs [][]byte, offset int) error {
	if c.webrtcMgr == nil {
		return nil
	}

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
		if err := c.webrtcMgr.SendPacket(disco.key(), b); err != nil {
			return err
		}
		c.metrics.outboundPacketsWebRTCTotal.Add(1)
		c.metrics.outboundBytesWebRTCTotal.Add(int64(len(b)))
		return nil
	}

	// Multi-packet batch path.
	size := 1 // magic byte
	for _, b := range buffs {
		size += 2 + len(b[offset:])
	}
	batch := make([]byte, size)
	batch[0] = WebRTCBatchMagic
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
	if err := c.webrtcMgr.SendPacket(disco.key(), batch); err != nil {
		return err
	}
	c.metrics.outboundPacketsWebRTCTotal.Add(int64(len(buffs)))
	c.metrics.outboundBytesWebRTCTotal.Add(totalBytes)
	return nil
}

// sendWebRTC sends a single packet over the WebRTC data channel to pubKey.
func (c *Conn) sendWebRTC(addr netip.AddrPort, pubKey key.NodePublic, b []byte) (sent bool, err error) {
	if c.webrtcMgr == nil {
		return false, nil
	}

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

	if err := c.webrtcMgr.SendPacket(disco.key(), b); err != nil {
		return false, err
	}

	c.metrics.outboundPacketsWebRTCTotal.Add(1)
	c.metrics.outboundBytesWebRTCTotal.Add(int64(len(b)))

	return true, nil
}

// receiveWebRTC is the [conn.ReceiveFunc] for the WebRTC path. It reads packets
// queued by [Conn.DeliverPacket] from webrtcRecvCh. It blocks until at least
// one packet is available, then drains as many additional packets as are
// immediately ready (up to len(buffs)).
func (c *connBind) receiveWebRTC(buffs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	// Block until the first packet arrives (or the channel is closed).
	wr, ok := <-c.webrtcRecvCh
	if !ok || c.isClosed() {
		return 0, net.ErrClosed
	}
	num := 0
	n, ep := c.processWebRTCReadResult(wr, buffs[num])
	if n > 0 {
		sizes[num] = n
		eps[num] = ep
		num++
	}
	// Drain any additional packets that are immediately available.
	for num < len(buffs) {
		select {
		case wr, ok = <-c.webrtcRecvCh:
			if !ok || c.isClosed() {
				if num > 0 {
					return num, nil
				}
				return 0, net.ErrClosed
			}
			n, ep = c.processWebRTCReadResult(wr, buffs[num])
			if n > 0 {
				sizes[num] = n
				eps[num] = ep
				num++
			}
		default:
			return num, nil
		}
	}
	return num, nil
}

// processWebRTCReadResult processes a WebRTC packet received from webrtcRecvCh.
// It's similar to processDERPReadResult but for WebRTC packets.
func (c *Conn) processWebRTCReadResult(wr webrtcReadResult, b []byte) (n int, ep *endpoint) {
	if wr.buf == nil {
		return 0, nil
	}

	n = wr.n
	ncopy := copy(b, wr.buf[:n])
	if ncopy != n {
		err := fmt.Errorf("received WebRTC packet of length %d that's too big for WireGuard buf size %d", n, ncopy)
		c.logf("magicsock: %v", err)
		return 0, nil
	}

	srcAddr := epAddr{ap: netip.AddrPortFrom(tailcfg.WebRTCMagicIPAddr, webrtcMagicPort)}

	// Check if this looks like a disco packet
	pt, isGeneveEncap := packetLooksLike(b[:n])
	if pt == packetLooksLikeDisco && !isGeneveEncap {
		c.handleDiscoMessage(b[:n], srcAddr, false, wr.src, discoRXPathWebRTC)
		return 0, nil
	}

	// Find the endpoint by node key
	var ok bool
	c.mu.Lock()
	ep, ok = c.peerMap.endpointForNodeKey(wr.src)
	c.mu.Unlock()

	if !ok {
		// We don't know anything about this node key
		return 0, nil
	}

	ep.noteRecvActivity(srcAddr, mono.Now())
	if update := c.connCounter.Load(); update != nil {
		update(0, netip.AddrPortFrom(ep.nodeAddr, 0), srcAddr.ap, 1, n, true)
	}

	c.metrics.inboundPacketsWebRTCTotal.Add(1)
	c.metrics.inboundBytesWebRTCTotal.Add(int64(n))

	return n, ep
}
