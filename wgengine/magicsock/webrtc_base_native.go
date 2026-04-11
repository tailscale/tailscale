//go:build !js

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"time"

	"github.com/pion/webrtc/v4"
	"tailscale.com/types/key"
)

func newWebRTCManagerBase(c *Conn) *webrtcManager {
	settingEngine := webrtc.SettingEngine{}

	// Use a 16 MiB SCTP receive buffer. The pion default (~32 KiB) becomes the
	// bottleneck at high throughput because SCTP's flow-control window is bounded
	// by this value.
	settingEngine.SetSCTPMaxReceiveBufferSize(16 * 1024 * 1024)

	// Enlarge the DTLS replay-protection window. The default (64) causes
	// legitimate packets to be dropped as duplicates when the sender gets ahead
	// of the receiver by more than 64 packets, which happens easily at Gbps speeds.
	settingEngine.SetDTLSReplayProtectionWindow(8192)

	// Lower the SCTP retransmission timeout ceiling. The default (1s+) causes
	// SCTP's congestion control to stall for a full second after any loss event,
	// which is catastrophic for throughput on a low-latency P2P link. 100ms is
	// still conservative but recovers much faster.
	settingEngine.SetSCTPRTOMax(100 * time.Millisecond)

	// DetachDataChannels lets us call dc.Detach() to get a raw io.ReadWriteCloser
	// instead of using OnMessage callbacks. The callback path allocates a new
	// DataChannelMessage struct and fires a goroutine wakeup per packet. The
	// detached path lets us Read() directly into pre-allocated buffers in a
	// tight goroutine loop, matching how the UDP receive path works.
	settingEngine.DetachDataChannels()

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

	return &webrtcManager{
		logf:                      c.logf,
		conn:                      c,
		peerConnectionsByEndpoint: make(map[*endpoint]*webrtcPeerState),
		peerConnectionsByDisco:    make(map[key.DiscoPublic]*webrtcPeerState),
		startConnectionCh:         make(chan *endpoint, 256),
		connectionReadyCh:         make(chan webrtcConnectionReadyEvent, 16),
		closeCh:                   make(chan struct{}),
		runLoopStoppedCh:          make(chan struct{}),
		api:                       api,
	}
}

func setOnError(dc *webrtc.DataChannel, fn func(error)) {
	dc.OnError(fn)
}
