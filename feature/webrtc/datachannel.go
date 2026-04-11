// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package webrtc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/pion/webrtc/v4"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/magicsock"
)

// SendPacket sends a packet over a WebRTC data channel.
// The hot path is lock-free: we take a read-lock (not write-lock) to look up
// the peer state, then do an atomic load for the detached channel. Multiple
// concurrent senders for different peers never contend.
func (m *manager) SendPacket(dst key.DiscoPublic, b []byte) error {
	m.mu.RLock()
	ps, ok := m.peerConnectionsByDisco[dst]
	m.mu.RUnlock()
	if !ok {
		return errors.New("no WebRTC connection")
	}

	// Native path: DetachDataChannels was enabled; use the raw io.ReadWriteCloser.
	if rw := ps.dcRW.Load(); rw != nil {
		if _, err := rw.Write(b); err != nil {
			return fmt.Errorf("send failed: %w", err)
		}
		return nil
	}

	// JS/fallback path: use DataChannel.Send() directly.
	dc := ps.dataChannel
	if dc == nil || dc.ReadyState() != webrtc.DataChannelStateOpen {
		return errors.New("data channel not ready")
	}
	return dc.Send(b)
}

// GetRemoteAddr returns the actual remote address for a connected WebRTC peer,
// or the zero value if there is no connected peer for the disco key.
func (m *manager) GetRemoteAddr(dst key.DiscoPublic) netip.AddrPort {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if ps, ok := m.peerConnectionsByDisco[dst]; ok && ps.state == stateConnected {
		return ps.remoteAddr
	}
	return netip.AddrPort{}
}

// deliverMsg delivers one DataChannel message to the receive pipeline.
// It handles both single packets and batches (WebRTCBatchMagic framing) so the logic
// is shared between the native detached-reader path and the JS/fallback
// OnMessage callback path.
func (m *manager) deliverMsg(ps *peerState, data []byte) {
	if len(data) == 0 {
		return
	}
	// Batch: [magic][2-byte BE len][pkt]...[2-byte BE len][pkt]
	if data[0] == magicsock.WebRTCBatchMagic {
		data = data[1:]
		for len(data) >= 2 {
			pktLen := int(binary.BigEndian.Uint16(data))
			data = data[2:]
			if pktLen > len(data) {
				m.logf("webrtc: batch framing error for peer %v: pktLen %d > remaining %d",
					ps.remoteDisco.ShortString(), pktLen, len(data))
				return
			}
			m.b.DeliverPacket(data[:pktLen], ps.remoteNodeKey)
			data = data[pktLen:]
		}
		return
	}
	m.b.DeliverPacket(data, ps.remoteNodeKey)
}

// runDataChannelReader is the per-peer receive loop used when DetachDataChannels
// is enabled (native builds). It reads directly from the detached io.ReadWriteCloser
// into a reused buffer, avoiding the per-message goroutine wakeup and allocation
// that the OnMessage callback path incurs.
func (m *manager) runDataChannelReader(ps *peerState, rwc io.ReadWriteCloser) {
	// Size the buffer to hold the largest possible batch.
	// 64 WireGuard packets × ~1420 bytes + framing < 100 KiB; 256 KiB is safe.
	buf := make([]byte, 256*1024)
	for {
		n, err := rwc.Read(buf)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
				m.logf("webrtc: data channel read error for peer %v: %v", ps.remoteDisco.ShortString(), err)
			}
			ps.dcRW.Store(nil)
			return
		}
		if n > 0 {
			m.deliverMsg(ps, buf[:n])
		}
	}
}
