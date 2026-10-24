//go:build !js

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package webrtc

import (
	"time"

	"github.com/pion/webrtc/v4"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/magicsock"
)

func newManagerBase(b magicsock.WebRTCBackend) *manager {
	settingEngine := webrtc.SettingEngine{}

	// Enlarge the SCTP flow-control receive window so more unacknowledged bytes
	// can be in flight; the default caps throughput on high-bandwidth links.
	settingEngine.SetSCTPMaxReceiveBufferSize(64 << 20) // 64 MiB

	// Keep the congestion window from collapsing to a tiny value, so throughput
	// doesn't have to ramp up from near-zero after idle periods or loss.
	settingEngine.SetSCTPMinCwnd(1 << 20) // 1 MiB

	// Widen the fast-retransmit window and the congestion-avoidance growth step
	// so the connection ramps up and recovers from loss faster.
	settingEngine.SetSCTPFastRtxWnd(256 << 10) // 256 KiB
	settingEngine.SetSCTPCwndCAStep(256 << 10) // 256 KiB

	// Enlarge the DTLS replay-protection window. The default (64) causes
	// legitimate packets to be dropped as duplicates when the sender gets ahead
	// of the receiver by more than 64 packets, which happens easily at Gbps speeds.
	settingEngine.SetDTLSReplayProtectionWindow(8192)

	// Lower the SCTP retransmission timeout ceiling. The default (1s+) stalls
	// congestion control for a full second after any loss event, which is
	// catastrophic for throughput on a low-latency P2P link.
	settingEngine.SetSCTPRTOMax(300 * time.Millisecond)

	// DetachDataChannels lets us call dc.Detach() to get a raw io.ReadWriteCloser
	// instead of using OnMessage callbacks. The callback path allocates a new
	// DataChannelMessage struct and fires a goroutine wakeup per packet. The
	// detached path lets us Read() directly into pre-allocated buffers in a
	// tight goroutine loop, matching how the UDP receive path works.
	settingEngine.DetachDataChannels()

	// Make detached-channel writes block (applying backpressure) when the SCTP
	// send buffer is full, instead of erroring and forcing the caller to spin.
	// Only takes effect with DetachDataChannels.
	settingEngine.EnableDataChannelBlockWrite(true)

	// SCTP includes a CRC32c checksum on every chunk. DTLS already provides
	// both integrity and authenticity for all data, so the SCTP checksum is
	// redundant CPU work. Zero-checksum mode (RFC 9260) removes it.
	settingEngine.EnableSCTPZeroChecksum(true)

	// Create MediaEngine (required even though we only use DataChannel)
	mediaEngine := &webrtc.MediaEngine{}

	// Create API with setting engine
	api := webrtc.NewAPI(
		webrtc.WithSettingEngine(settingEngine),
		webrtc.WithMediaEngine(mediaEngine),
	)

	return &manager{
		logf:                   b.Logf,
		b:                      b,
		peerConnectionsByPeer:  make(map[magicsock.WebRTCPeer]*peerState),
		peerConnectionsByDisco: make(map[key.DiscoPublic]*peerState),
		startConnectionCh:      make(chan magicsock.WebRTCPeer, 256),
		closeCh:                make(chan struct{}),
		runLoopStoppedCh:       make(chan struct{}),
		api:                    api,
	}
}
