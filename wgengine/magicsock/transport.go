// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"

	"tailscale.com/feature"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// This file defines magicsock's extension point for pluggable third-party
// transports: alternative connectivity paths (e.g. WebRTC) that magicsock can
// send and receive WireGuard traffic over without having any compile-time
// dependency on their implementation.
//
// A transport implementation lives in its own package (e.g.
// github.com/adrianosela/ts-transport-webrtc) and registers itself from its init
// via [RegisterTransport]. magicsock has no knowledge of any concrete
// transport; it only ever sees the [Transport], [TransportHost], and
// [TransportPeer] interfaces. A transport is linked in only when a program
// blank-imports its package; otherwise it is simply not registered and the path
// is absent.
//
// Each registered transport is assigned a synthetic magic IP from the reserved
// block (see [tailcfg.TransportMagicIP]). That magic IP flows through the
// existing endpoint/disco path-selection machinery exactly like the DERP magic
// IP does: it is never sent on the wire, it only tags which local path a packet
// took.

// Transport is a pluggable connectivity path registered via [RegisterTransport]
// and consumed by magicsock. It is implemented by a transport package (e.g.
// github.com/adrianosela/ts-transport-webrtc) and constructed with a
// [TransportHost] giving it the magicsock capabilities it needs. All methods
// must be safe for concurrent use.
type Transport interface {
	// Close shuts down the transport and all its peer connections.
	Close() error

	// EnsureConnecting starts (or retries) a connection to peer if one is not
	// already in progress or established. Safe to call from the hot send path.
	// The transport decides for itself whether a given peer is eligible.
	EnsureConnecting(peer TransportPeer)

	// SendPacket sends b to the connected peer identified by dst.
	SendPacket(dst key.DiscoPublic, b []byte) error

	// GetRemoteAddr returns the selected remote address (host:port) for a
	// connected peer, or "" if not connected. Used for status display only.
	GetRemoteAddr(dst key.DiscoPublic) string

	// HandleSignal dispatches a signaling message (an opaque, transport-owned
	// payload) received over disco from fromDisco. The payload is whatever the
	// transport's own send side put in a [disco.TransportSignal]; magicsock does
	// not interpret it.
	HandleSignal(fromDisco key.DiscoPublic, payload []byte)
}

// TransportHost is the set of magicsock capabilities a [Transport] needs. One
// TransportHost is handed to each registered transport at construction time; it
// is bound to that transport's identity, so [TransportHost.SendSignal],
// [TransportHost.DeliverPacket], and [TransportHost.SetChannelReady] act on
// behalf of that specific transport. It is implemented by *Conn (via a small
// per-transport binding). All methods must be safe for concurrent use.
type TransportHost interface {
	// LocalDiscoKey returns this node's current disco public key.
	LocalDiscoKey() key.DiscoPublic

	// PeerForDisco returns the [TransportPeer] for the given disco key, or
	// ok=false if no endpoint is known for it.
	PeerForDisco(key.DiscoPublic) (p TransportPeer, ok bool)

	// SendSignal sends an opaque signaling payload to the peer identified by
	// dst, over DERP. The host tags the message with this transport's name so
	// the receiving side can dispatch it back to the right transport.
	SendSignal(dst key.DiscoPublic, payload []byte) error

	// DeliverPacket hands a decrypted data packet from this transport to the
	// magicsock receive pipeline, attributed to the given source node key.
	DeliverPacket(b []byte, src key.NodePublic)

	// SetChannelReady reports whether this transport currently has an open
	// channel to peer. While ready, magicsock re-probes this transport's path
	// each disco heartbeat so it can be selected, and re-selected after any
	// fallback, based on disco pong evidence. Path selection and liveness are
	// otherwise driven entirely by disco ping/pong, not by this signal.
	SetChannelReady(peer TransportPeer, ready bool)

	// Disabled reports whether pluggable transports should be suppressed (e.g.
	// a debug knob is set). When true the transport should fall back to DERP.
	Disabled() bool

	// Logf logs a message.
	Logf(format string, args ...any)
}

// TransportPeer abstracts a single magicsock endpoint for a [Transport]. A
// TransportPeer is used as a map key by transports, so implementations must be
// comparable and stable for the lifetime of the endpoint. It is implemented by
// *endpoint.
type TransportPeer interface {
	// DiscoKey returns the peer's current disco public key, or ok=false if the
	// peer has no disco key yet.
	DiscoKey() (dk key.DiscoPublic, ok bool)

	// NodeKey returns the peer's node public key (used for WireGuard).
	NodeKey() key.NodePublic

	// NodeAddr returns the peer's Tailscale IP, for logging only.
	NodeAddr() netip.Addr

	// IsJS reports whether the peer runs on a JavaScript/Wasm platform (its
	// last-known Hostinfo OS is "js"). A transport may use this to decide
	// eligibility (e.g. WebRTC is only attempted when at least one side is JS).
	IsJS() bool

	// DERPReady reports whether the peer currently has a valid DERP address,
	// which is required before disco-based signaling can succeed.
	DERPReady() bool
}

// TransportBatchMagic is the first byte of a batched transport message, framed
// as [magic][2-byte BE len][pkt]...  It must not collide with the first byte of
// the other things that can arrive on a transport: WireGuard packets start with
// 0x01–0x04 and disco packets start with 0x54 ('T'). 'W' collides with neither.
// It is the single source of truth for the framing byte, shared with each
// transport's receive path. (See [Conn.sendTransportBatch].)
const TransportBatchMagic = byte('W')

// Option customizes a transport registration. See [WithPriorityOverDirect].
type Option func(*registeredTransport)

// WithPriorityOverDirect ranks the transport's path above a direct UDP path
// during path selection (see [betterAddr]): transport > Direct > DERP. Use it
// for a transport expected to outperform direct UDP when available, e.g. a LAN
// TCP transport on an OS whose TCP stack is far faster than its UDP path.
//
// By default (without this option) a transport ranks below a direct UDP path
// but above DERP and peer-relay (Direct > transport > DERP), which is right for
// a transport that is a NAT-traversal aid (e.g. WebRTC), where a direct UDP
// path, when it exists, is still best. A direct UDP path is the natural pivot;
// finer ordering is decided by measured disco latency.
func WithPriorityOverDirect() Option {
	return func(rt *registeredTransport) { rt.aboveDirect = true }
}

// registeredTransport is one entry in the process-global transport registry.
type registeredTransport struct {
	name        string
	ctor        func(TransportHost) Transport
	aboveDirect bool // ranks above a direct UDP path; see WithPriorityOverDirect
}

// registeredTransports is the set of transports linked into the binary, in
// registration order. Registration happens from transport packages' init
// functions, before any [Conn] is created, so it needs no locking. The order is
// process-local; it only determines each transport's local magic-IP index and
// never goes on the wire (signaling is dispatched by transport name).
var registeredTransports []registeredTransport

// transportsFeatureName is the [tailscale.com/feature] capability name recorded
// when at least one pluggable transport is linked in. It is a single capability
// shared by all transports (an individual transport is identified by its own
// name, not a feature), so it is registered once here rather than by each
// transport package — [feature.Register] panics on a duplicate name.
const transportsFeatureName = "pluggable-transports"

// RegisterTransport registers a pluggable transport constructor under the given
// name. It is meant to be called from a transport package's init, e.g.:
//
//	func init() {
//		magicsock.RegisterTransport("webrtc", newTransport)
//	}
//
// The name is the transport's identity: it selects the transport's magic-IP
// slot locally and is carried in [disco.TransportSignal] so the receiving side
// dispatches signaling back to the same transport. The first call also records
// the "pluggable-transports" feature (see [transportsFeatureName]); transport
// packages must not call [feature.Register] themselves.
//
// Options customize the registration; see [WithPriorityOverDirect]. By
// default a transport ranks below a direct UDP path (but above DERP).
//
// Every [Conn] created afterward constructs one instance of each registered
// transport. RegisterTransport panics if name is empty, already registered, or
// if more than [tailcfg.MaxPluggableTransports] transports are registered.
func RegisterTransport(name string, ctor func(TransportHost) Transport, opts ...Option) {
	if name == "" {
		panic("magicsock: RegisterTransport with empty name")
	}
	if ctor == nil {
		panic("magicsock: RegisterTransport with nil constructor")
	}
	for _, rt := range registeredTransports {
		if rt.name == name {
			panic("magicsock: duplicate transport registration for " + name)
		}
	}
	if len(registeredTransports) >= tailcfg.MaxPluggableTransports {
		panic("magicsock: too many registered transports")
	}
	// Record the shared capability once, on the first registration.
	if !feature.IsRegistered(transportsFeatureName) {
		feature.Register(transportsFeatureName)
	}
	rt := registeredTransport{name: name, ctor: ctor}
	for _, opt := range opts {
		opt(&rt)
	}
	registeredTransports = append(registeredTransports, rt)
}

// transportAboveDirect reports whether the transport served by magic IP a was
// registered with [WithPriorityOverDirect]. It returns false when a is
// not a transport magic IP or its transport isn't registered (the default,
// below-direct, ranking). Used by [betterAddr] and the heartbeat probe.
func transportAboveDirect(a netip.Addr) bool {
	idx, ok := tailcfg.IsTransportMagicIP(a)
	if !ok || idx >= len(registeredTransports) {
		return false
	}
	return registeredTransports[idx].aboveDirect
}

// transportInstance is one live transport within a [Conn]. idx is the
// transport's registration index (its position in registeredTransports), which
// is the canonical identifier used everywhere: it determines the magic IP (via
// [tailcfg.TransportMagicIP]), tags read results and signaling, and keys the
// per-endpoint readiness map. It is NOT necessarily a dense index, since a
// transport whose constructor returned nil is skipped.
type transportInstance struct {
	name    string
	magicIP netip.Addr
	idx     int
	t       Transport
}

// transportHost is the per-transport [TransportHost] binding handed to a
// transport at construction. It carries the transport's index so host methods
// that are transport-specific (SendSignal, DeliverPacket, SetChannelReady) act
// on behalf of the right transport.
type transportHost struct {
	c   *Conn
	idx int
}

// initTransports constructs one instance of each registered transport, assigns
// each a magic IP from the reserved block, and records them on c. It is a no-op
// (leaving c.transports empty) when no transport packages are linked in.
// magicsock has no compile-time dependency on any transport; an empty registry
// is what disables the feature.
func (c *Conn) initTransports() {
	if len(registeredTransports) == 0 {
		return
	}
	c.transports = make(map[int]transportInstance, len(registeredTransports))
	c.magicIPToTransport = make(map[netip.Addr]int, len(registeredTransports))
	for i, rt := range registeredTransports {
		magicIP := tailcfg.TransportMagicIP(i)
		host := &transportHost{c: c, idx: i}
		t := rt.ctor(host)
		if t == nil {
			c.logf("magicsock: transport %q failed to initialize", rt.name)
			continue
		}
		c.logf("magicsock: initialized pluggable transport %q at %v", rt.name, magicIP)
		c.transports[i] = transportInstance{
			name:    rt.name,
			magicIP: magicIP,
			idx:     i,
			t:       t,
		}
		c.magicIPToTransport[magicIP] = i
	}
}

// transportByMagicIP returns the live transport instance whose magic IP is a,
// or ok=false if a is not a transport magic IP for a linked-in transport.
func (c *Conn) transportByMagicIP(a netip.Addr) (inst transportInstance, ok bool) {
	idx, ok := c.magicIPToTransport[a]
	if !ok {
		return transportInstance{}, false
	}
	return c.transports[idx], true
}

// transportByName returns the live transport instance registered under name, or
// ok=false if no such transport is linked in.
func (c *Conn) transportByName(name string) (inst transportInstance, ok bool) {
	for _, inst := range c.transports {
		if inst.name == name {
			return inst, true
		}
	}
	return transportInstance{}, false
}
