// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package largetailnet provides reusable building blocks for in-process
// benchmarks and stress tests that drive a single tailnet client (typically a
// [tsnet.Server]) with a synthetic large-tailnet MapResponse stream.
//
// A [Streamer] takes over the map long-poll on a [testcontrol.Server] via the
// AltMapStream hook: it sends one initial MapResponse announcing the self
// node and N synthetic peers, and then forwards caller-supplied delta
// MapResponses on the same stream until ctx is done.
//
// The package is designed so that a benchmark can:
//
//   - Build a [Streamer] with the desired peer count.
//   - Stand up a [testcontrol.Server] with the streamer's [Streamer.AltMapStream]
//     installed.
//   - Stand up a [tsnet.Server] pointed at the testcontrol; its Up call
//     blocks until the initial netmap has been processed.
//   - Reset the benchmark timer and drive add/remove deltas with
//     [Streamer.SendDelta] and [Streamer.AllocPeer].
package largetailnet

import (
	"context"
	cryptorand "crypto/rand"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"go4.org/mem"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
)

// SelfUserID is the synthetic [tailcfg.UserID] assigned to the self node and
// to every initial peer produced by [Streamer]. Tests that build their own
// peers via [MakePeer] should pass this value.
const SelfUserID tailcfg.UserID = 1_000_000

// Streamer drives a controlled MapResponse stream to a single client via
// [testcontrol.Server.AltMapStream]. It synthesizes an initial netmap with N
// peers and forwards caller-supplied delta MapResponses on the same stream.
//
// A Streamer is single-shot: it expects exactly one map long-poll over its
// lifetime and is not safe for re-use across multiple clients.
type Streamer struct {
	n       int
	derpMap *tailcfg.DERPMap

	started     chan struct{} // closed when the alt-map-stream callback first fires
	initialDone chan struct{} // closed after initial MapResponse has been written
	deltas      chan *tailcfg.MapResponse

	// nextID is the next free node ID. It starts at N+2 (1 is the self
	// node, 2..N+1 are the initial peers) and is bumped by AllocPeer.
	nextID atomic.Int64
}

// New constructs a Streamer that will produce an initial netmap with n peers
// and a self node when its AltMapStream callback first fires. derpMap is
// included verbatim in the initial MapResponse.
func New(n int, derpMap *tailcfg.DERPMap) *Streamer {
	s := &Streamer{
		n:           n,
		derpMap:     derpMap,
		started:     make(chan struct{}),
		initialDone: make(chan struct{}),
		// Buffered so a benchmark loop body that does send-then-wait
		// doesn't block on the channel under steady state.
		deltas: make(chan *tailcfg.MapResponse, 64),
	}
	s.nextID.Store(int64(n) + 2)
	return s
}

// AltMapStream returns a callback suitable for [testcontrol.Server.AltMapStream].
// On the first streaming long-poll it sends the initial big MapResponse and
// then forwards deltas enqueued via [Streamer.SendDelta] until ctx is done.
// Non-streaming "lite" polls are answered with an empty MapResponse so they
// complete quickly. The streamer is single-shot: any later streaming polls
// are kept alive but produce no further messages.
func (s *Streamer) AltMapStream() testcontrol.AltMapStreamFunc {
	return func(ctx context.Context, w testcontrol.MapStreamWriter, req *tailcfg.MapRequest) {
		if !req.Stream {
			_ = w.SendMapMessage(&tailcfg.MapResponse{})
			return
		}

		select {
		case <-s.started:
			// Re-poll after the original stream ended. Keep the
			// connection alive so the client doesn't churn.
			<-ctx.Done()
			return
		default:
			close(s.started)
		}

		if err := s.sendInitial(w, req); err != nil {
			// Make the failure loud rather than wedging the
			// caller's [tsnet.Server.Up] on a silent retry loop.
			panic(fmt.Sprintf("largetailnet: sendInitial: %v", err))
		}
		close(s.initialDone)

		for {
			select {
			case <-ctx.Done():
				return
			case mr := <-s.deltas:
				if err := w.SendMapMessage(mr); err != nil {
					<-ctx.Done()
					return
				}
			}
		}
	}
}

// AwaitInitialSent blocks until the initial big MapResponse has been written
// to the wire. Note this is not the same as "the client has finished
// processing it"; for that, callers should rely on [tsnet.Server.Up]
// returning, or watch the IPN bus.
func (s *Streamer) AwaitInitialSent(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.initialDone:
		return nil
	}
}

// SendDelta enqueues mr for delivery on the active MapResponse stream. It
// blocks if the internal queue is full or the stream hasn't started yet.
func (s *Streamer) SendDelta(ctx context.Context, mr *tailcfg.MapResponse) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case s.deltas <- mr:
		return nil
	}
}

// AllocPeer returns a fresh synthetic peer node with a never-before-used
// [tailcfg.NodeID]. It's intended for use in PeersChanged deltas.
func (s *Streamer) AllocPeer() *tailcfg.Node {
	return MakePeer(tailcfg.NodeID(s.nextID.Add(1)-1), SelfUserID)
}

// SelfNodeID returns the [tailcfg.NodeID] used for the self node in the
// initial netmap.
func (s *Streamer) SelfNodeID() tailcfg.NodeID { return 1 }

// sendInitial writes the big initial MapResponse with s.n peers.
func (s *Streamer) sendInitial(w testcontrol.MapStreamWriter, req *tailcfg.MapRequest) error {
	selfNodeID := s.SelfNodeID()
	selfIP4 := node4(selfNodeID)
	selfIP6 := node6(selfNodeID)

	peers := make([]*tailcfg.Node, 0, s.n)
	for i := 0; i < s.n; i++ {
		peers = append(peers, MakePeer(tailcfg.NodeID(i+2), SelfUserID))
	}

	now := time.Now().UTC()
	selfNode := &tailcfg.Node{
		ID:                selfNodeID,
		StableID:          "largetailnet-self",
		Name:              "self.largetailnet.ts.net.",
		User:              SelfUserID,
		Key:               req.NodeKey,
		KeyExpiry:         now.Add(24 * time.Hour),
		Machine:           randMachineKey(), // fake; client doesn't verify
		DiscoKey:          req.DiscoKey,
		MachineAuthorized: true,
		Addresses:         []netip.Prefix{selfIP4, selfIP6},
		AllowedIPs:        []netip.Prefix{selfIP4, selfIP6},
		CapMap:            map[tailcfg.NodeCapability][]tailcfg.RawMessage{},
	}

	initial := &tailcfg.MapResponse{
		KeepAlive: false,
		Node:      selfNode,
		DERPMap:   s.derpMap,
		Peers:     peers,
		PacketFilter: []tailcfg.FilterRule{{
			// Accept-all filter so the client isn't logging packet-filter
			// failures; this is a benchmark harness, not a security test.
			SrcIPs:   []string{"*"},
			DstPorts: []tailcfg.NetPortRange{{IP: "*", Ports: tailcfg.PortRangeAny}},
		}},
		DNSConfig: &tailcfg.DNSConfig{},
		Domain:    "largetailnet.ts.net",
		UserProfiles: []tailcfg.UserProfile{{
			ID:          SelfUserID,
			LoginName:   "largetailnet@example.com",
			DisplayName: "largetailnet",
		}},
		ControlTime: &now,
	}
	return w.SendMapMessage(initial)
}

// MakePeer constructs a synthetic [tailcfg.Node] for the given NodeID and
// UserID. The peer's node/disco/machine keys are derived from random bytes
// via the *PublicFromRaw32 constructors rather than via key.New*().Public(),
// which avoids the per-peer Curve25519 ScalarBaseMult and lets the harness
// construct hundreds of thousands of peers in a few hundred milliseconds.
// The client never crypto-validates these keys in the bench, so opaque
// random bytes are sufficient.
func MakePeer(nid tailcfg.NodeID, user tailcfg.UserID) *tailcfg.Node {
	v4, v6 := node4(nid), node6(nid)
	name := fmt.Sprintf("peer-%d", nid)
	return &tailcfg.Node{
		ID:                nid,
		StableID:          tailcfg.StableNodeID(name),
		Name:              name + ".largetailnet.ts.net.",
		Key:               randNodeKey(),
		MachineAuthorized: true,
		DiscoKey:          randDiscoKey(),
		Machine:           randMachineKey(),
		Addresses:         []netip.Prefix{v4, v6},
		AllowedIPs:        []netip.Prefix{v4, v6},
		User:              user,
		// Hostinfo must be non-nil: LocalBackend.populatePeerStatus
		// dereferences it via HostinfoView.Hostname unconditionally.
		Hostinfo: (&tailcfg.Hostinfo{Hostname: name}).View(),
	}
}

func randNodeKey() key.NodePublic {
	var b [32]byte
	cryptorand.Read(b[:])
	return key.NodePublicFromRaw32(mem.B(b[:]))
}

func randDiscoKey() key.DiscoPublic {
	var b [32]byte
	cryptorand.Read(b[:])
	return key.DiscoPublicFromRaw32(mem.B(b[:]))
}

func randMachineKey() key.MachinePublic {
	var b [32]byte
	cryptorand.Read(b[:])
	return key.MachinePublicFromRaw32(mem.B(b[:]))
}

func node4(nid tailcfg.NodeID) netip.Prefix {
	return netip.PrefixFrom(
		netip.AddrFrom4([4]byte{100, 100 + byte(nid>>16), byte(nid >> 8), byte(nid)}),
		32)
}

func node6(nid tailcfg.NodeID) netip.Prefix {
	a := tsaddr.TailscaleULARange().Addr().As16()
	a[13] = byte(nid >> 16)
	a[14] = byte(nid >> 8)
	a[15] = byte(nid)
	return netip.PrefixFrom(netip.AddrFrom16(a), 128)
}
