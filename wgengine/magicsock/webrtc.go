// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"

	"tailscale.com/disco"
	"tailscale.com/feature"
	"tailscale.com/types/key"
)

// This file defines magicsock's extension point for the WebRTC
// connectivity path. The implementation lives in feature/webrtc, which
// registers itself via HookNewWebRTCManager from its init. magicsock itself
// has no dependency on pion/WebRTC; when feature/webrtc is not linked in (e.g.
// the ts_omit_webrtc build tag, or a tsnet build that doesn't import it), the
// hook is unset and webrtcMgr stays nil.

// HookNewWebRTCManager, if set by feature/webrtc, constructs a [WebRTCManager]
// for the given [WebRTCBackend]. It returns nil if the manager fails to
// initialize.
var HookNewWebRTCManager feature.Hook[func(WebRTCBackend) WebRTCManager]

// WebRTCManager manages WebRTC connections for a [Conn]. It is implemented by
// feature/webrtc and consumed by magicsock via the webrtcMgr field.
type WebRTCManager interface {
	// Close shuts down the manager and all its peer connections.
	Close() error

	// EnsureConnecting starts (or retries) a WebRTC connection to peer if one
	// is not already in progress or established. Safe to call from the hot
	// send path.
	EnsureConnecting(peer WebRTCPeer)

	// SendPacket sends b to the connected WebRTC peer identified by dst.
	SendPacket(dst key.DiscoPublic, b []byte) error

	// GetRemoteAddr returns the actual remote address for a connected WebRTC
	// peer, or the zero value if not connected.
	GetRemoteAddr(dst key.DiscoPublic) netip.AddrPort

	// HandleSignal dispatches a WebRTC signaling message (of the given kind,
	// with a JSON-encoded payload) received over disco from fromDisco.
	HandleSignal(fromDisco key.DiscoPublic, kind disco.WebRTCSignalKind, payload []byte)
}

// WebRTCBackend is the set of magicsock capabilities the WebRTC manager needs.
// It is implemented by *Conn. All methods must be safe for concurrent use.
type WebRTCBackend interface {
	// LocalDiscoKey returns this node's current disco public key.
	LocalDiscoKey() key.DiscoPublic

	// PeerForDisco returns the [WebRTCPeer] for the given disco key, or
	// ok=false if no endpoint is known for it.
	PeerForDisco(key.DiscoPublic) (p WebRTCPeer, ok bool)

	// SendSignal sends a WebRTC signaling disco message to the peer identified
	// by dst, over DERP.
	SendSignal(dst key.DiscoPublic, msg disco.Message) error

	// DeliverPacket hands a decrypted WebRTC data-channel packet to the
	// magicsock receive pipeline, attributed to the given source node key.
	DeliverPacket(b []byte, src key.NodePublic)

	// DisableWebRTC reports whether WebRTC should be suppressed (e.g. the
	// TS_DEBUG_ALWAYS_USE_DERP debug knob is set).
	DisableWebRTC() bool

	// Logf logs a message.
	Logf(format string, args ...any)
}

// WebRTCPeer abstracts a single magicsock endpoint for the WebRTC manager. A
// WebRTCPeer is used as a map key by the manager, so implementations must be
// comparable and stable for the lifetime of the endpoint. It is implemented by
// *endpoint.
type WebRTCPeer interface {
	// DiscoKey returns the peer's current disco public key, or ok=false if the
	// peer has no disco key yet.
	DiscoKey() (dk key.DiscoPublic, ok bool)

	// NodeKey returns the peer's node public key (used for WireGuard).
	NodeKey() key.NodePublic

	// NodeAddr returns the peer's Tailscale IP, for logging only.
	NodeAddr() netip.Addr

	// IsJS reports whether the peer runs on a JavaScript/Wasm platform (its
	// last-known Hostinfo OS is "js"). WebRTC is only attempted when at least
	// one side of a connection is a JS peer; native-to-native peers use direct
	// UDP or DERP instead.
	IsJS() bool

	// DERPReady reports whether the peer currently has a valid DERP address,
	// which is required before signaling can succeed.
	DERPReady() bool

	// SetWebRTCPath marks the WebRTC magic address as the peer's best path if
	// it is better than the peer's current best path.
	SetWebRTCPath()

	// ClearWebRTCPath resets the peer's best path if it is currently the
	// WebRTC magic address, so traffic falls back to DERP.
	ClearWebRTCPath()
}

// WebRTCBatchMagic is the first byte of a batched WebRTC SCTP message, framed
// as [magic][2-byte BE len][pkt]...  It must not collide with the first byte of
// the other things that can arrive on the data channel: WireGuard packets start
// with 0x01–0x04 and disco packets start with 0x54 ('T'). 'W' collides with
// neither. It is the single source of truth for the framing byte, shared with
// feature/webrtc's receive path.
const WebRTCBatchMagic = byte('W')

// initWebRTC initializes the WebRTC manager if feature/webrtc is linked in
// (i.e. it registered HookNewWebRTCManager from its init). It is a no-op,
// leaving c.webrtcMgr nil, otherwise. magicsock has no compile-time dependency
// on pion/WebRTC; the hook being unset is what disables the feature, so no
// build tag is needed here.
func (c *Conn) initWebRTC() {
	newMgr, ok := HookNewWebRTCManager.GetOk()
	if !ok {
		return
	}
	c.logf("magicsock: initializing WebRTC with disco signaling")
	c.webrtcMgr = newMgr(c)
	if c.webrtcMgr == nil {
		c.logf("magicsock: failed to initialize WebRTC manager")
	}
}
