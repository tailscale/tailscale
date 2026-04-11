//go:build !js

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"time"

	"github.com/pion/dtls/v3"
	dtlselliptic "github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/ice/v4"
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

	// Pin to AES-128-GCM, the cheapest DTLS cipher suite (~0.5 cycles/byte
	// with AES-NI). DTLS encryption can't be disabled in WebRTC, but this
	// ensures we use hardware-accelerated AES and avoid negotiation overhead.
	// The traffic is already WireGuard-encrypted, so this is purely to
	// satisfy the WebRTC mandatory encryption requirement.
	settingEngine.SetDTLSCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)

	// Pin ECDHE key exchange to X25519, the fastest curve. Avoids curve
	// negotiation during the DTLS handshake.
	settingEngine.SetDTLSEllipticCurves(dtlselliptic.X25519)

	// Skip the DTLS HelloVerify roundtrip. Normally DTLS does an extra
	// ClientHello/HelloVerifyRequest exchange for DoS protection. Both
	// sides are already authenticated via disco keys, so we save one RTT.
	settingEngine.SetDTLSInsecureSkipHelloVerify(true)

	// Lower the DTLS handshake retransmission interval from the default 1s.
	// If the initial handshake packet is lost (e.g. still going via DERP
	// relay), 250ms recovers quickly without being so aggressive that it
	// causes spurious retransmits on higher-latency paths.
	settingEngine.SetDTLSRetransmissionInterval(250 * time.Millisecond)

	// Disable ICE TCP candidates. We only want UDP for WireGuard traffic.
	settingEngine.DisableActiveTCP(true)

	// TODO(adriano): remove after demo. Restrict ICE to IPv4-only because
	// the browser/WASM peer does not handle IPv6 ICE candidates correctly,
	// causing the connection to break when an IPv6 candidate is selected.
	settingEngine.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})

	// Disable mDNS candidate gathering. Peer addresses are already known
	// via the Tailscale coordination layer; mDNS adds latency to ICE
	// gathering for no benefit.
	settingEngine.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)

	// Accept the first working ICE candidate immediately instead of waiting
	// for potentially better ones. Gets the DataChannel open faster.
	settingEngine.SetHostAcceptanceMinWait(0)
	settingEngine.SetSrflxAcceptanceMinWait(0)

	// Set the receive MTU to match typical network MTU. The default (8192)
	// allocates oversized buffers per read.
	settingEngine.SetReceiveMTU(1500)

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
