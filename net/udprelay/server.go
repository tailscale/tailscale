// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package udprelay contains constructs for relaying Disco and WireGuard packets
// between Tailscale clients over UDP. This package is currently considered
// experimental.
package udprelay

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"go4.org/mem"
	"tailscale.com/disco"
	"tailscale.com/net/packet"
	"tailscale.com/net/udprelay/endpoint"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
)

const (
	// defaultBindLifetime is somewhat arbitrary. We attempt to account for
	// high latency between client and [Server], and high latency between
	// clients over side channels, e.g. DERP, used to exchange
	// [endpoint.ServerEndpoint] details. So, a total of 3 paths with
	// potentially high latency. Using a conservative 10s "high latency" bounds
	// for each path we end up at a 30s total. It is worse to set an aggressive
	// bind lifetime as this may lead to path discovery failure, vs dealing with
	// a slight increase of [Server] resource utilization (VNIs, RAM, etc) while
	// tracking endpoints that won't bind.
	defaultBindLifetime        = time.Second * 30
	defaultSteadyStateLifetime = time.Minute * 5
)

// Server implements an experimental UDP relay server.
type Server struct {
	// disco keypair used as part of 3-way bind handshake
	disco       key.DiscoPrivate
	discoPublic key.DiscoPublic

	bindLifetime        time.Duration
	steadyStateLifetime time.Duration

	// addrPorts contains the ip:port pairs returned as candidate server
	// endpoints in response to an allocation request.
	addrPorts []netip.AddrPort

	uc *net.UDPConn

	closeOnce sync.Once
	wg        sync.WaitGroup
	closeCh   chan struct{}
	closed    bool

	mu        sync.Mutex // guards the following fields
	lamportID uint64
	vniPool   []uint32 // the pool of available VNIs
	byVNI     map[uint32]*serverEndpoint
	byDisco   map[pairOfDiscoPubKeys]*serverEndpoint
}

// pairOfDiscoPubKeys is a pair of key.DiscoPublic. It must be constructed via
// newPairOfDiscoPubKeys to ensure lexicographical ordering.
type pairOfDiscoPubKeys [2]key.DiscoPublic

func (p pairOfDiscoPubKeys) String() string {
	return fmt.Sprintf("%s <=> %s", p[0].ShortString(), p[1].ShortString())
}

func newPairOfDiscoPubKeys(discoA, discoB key.DiscoPublic) pairOfDiscoPubKeys {
	pair := pairOfDiscoPubKeys([2]key.DiscoPublic{discoA, discoB})
	slices.SortFunc(pair[:], func(a, b key.DiscoPublic) int {
		return a.Compare(b)
	})
	return pair
}

// serverEndpoint contains Server-internal [endpoint.ServerEndpoint] state.
// serverEndpoint methods are not thread-safe.
type serverEndpoint struct {
	// discoPubKeys contains the key.DiscoPublic of the served clients. The
	// indexing of this array aligns with the following fields, e.g.
	// discoSharedSecrets[0] is the shared secret to use when sealing
	// Disco protocol messages for transmission towards discoPubKeys[0].
	discoPubKeys       pairOfDiscoPubKeys
	discoSharedSecrets [2]key.DiscoShared
	handshakeState     [2]disco.BindUDPRelayHandshakeState
	addrPorts          [2]netip.AddrPort
	lastSeen           [2]time.Time // TODO(jwhited): consider using mono.Time
	challenge          [2][disco.BindUDPRelayEndpointChallengeLen]byte

	lamportID   uint64
	vni         uint32
	allocatedAt time.Time
}

func (e *serverEndpoint) handleDiscoControlMsg(from netip.AddrPort, senderIndex int, discoMsg disco.Message, uw udpWriter, serverDisco key.DiscoPublic) {
	if senderIndex != 0 && senderIndex != 1 {
		return
	}
	handshakeState := e.handshakeState[senderIndex]
	if handshakeState == disco.BindUDPRelayHandshakeStateAnswerReceived {
		// this sender is already bound
		return
	}
	switch discoMsg := discoMsg.(type) {
	case *disco.BindUDPRelayEndpoint:
		switch handshakeState {
		case disco.BindUDPRelayHandshakeStateInit:
			// set sender addr
			e.addrPorts[senderIndex] = from
			fallthrough
		case disco.BindUDPRelayHandshakeStateChallengeSent:
			if from != e.addrPorts[senderIndex] {
				// this is a later arriving bind from a different source, or
				// a retransmit and the sender's source has changed, discard
				return
			}
			m := new(disco.BindUDPRelayEndpointChallenge)
			copy(m.Challenge[:], e.challenge[senderIndex][:])
			reply := make([]byte, packet.GeneveFixedHeaderLength, 512)
			gh := packet.GeneveHeader{Control: true, VNI: e.vni, Protocol: packet.GeneveProtocolDisco}
			err := gh.Encode(reply)
			if err != nil {
				return
			}
			reply = append(reply, disco.Magic...)
			reply = serverDisco.AppendTo(reply)
			box := e.discoSharedSecrets[senderIndex].Seal(m.AppendMarshal(nil))
			reply = append(reply, box...)
			uw.WriteMsgUDPAddrPort(reply, nil, from)
			// set new state
			e.handshakeState[senderIndex] = disco.BindUDPRelayHandshakeStateChallengeSent
			return
		default:
			// disco.BindUDPRelayEndpoint is unexpected in all other handshake states
			return
		}
	case *disco.BindUDPRelayEndpointAnswer:
		switch handshakeState {
		case disco.BindUDPRelayHandshakeStateChallengeSent:
			if from != e.addrPorts[senderIndex] {
				// sender source has changed
				return
			}
			if !bytes.Equal(discoMsg.Answer[:], e.challenge[senderIndex][:]) {
				// bad answer
				return
			}
			// sender is now bound
			// TODO: Consider installing a fast path via netfilter or similar to
			// relay (NAT) data packets for this serverEndpoint.
			e.handshakeState[senderIndex] = disco.BindUDPRelayHandshakeStateAnswerReceived
			// record last seen as bound time
			e.lastSeen[senderIndex] = time.Now()
			return
		default:
			// disco.BindUDPRelayEndpointAnswer is unexpected in all other handshake
			// states, or we've already handled it
			return
		}
	default:
		// unexpected Disco message type
		return
	}
}

func (e *serverEndpoint) handleSealedDiscoControlMsg(from netip.AddrPort, b []byte, uw udpWriter, serverDisco key.DiscoPublic) {
	senderRaw, isDiscoMsg := disco.Source(b)
	if !isDiscoMsg {
		// Not a Disco message
		return
	}
	sender := key.DiscoPublicFromRaw32(mem.B(senderRaw))
	senderIndex := -1
	switch {
	case sender.Compare(e.discoPubKeys[0]) == 0:
		senderIndex = 0
	case sender.Compare(e.discoPubKeys[1]) == 0:
		senderIndex = 1
	default:
		// unknown Disco public key
		return
	}

	const headerLen = len(disco.Magic) + key.DiscoPublicRawLen
	discoPayload, ok := e.discoSharedSecrets[senderIndex].Open(b[headerLen:])
	if !ok {
		// unable to decrypt the Disco payload
		return
	}

	discoMsg, err := disco.Parse(discoPayload)
	if err != nil {
		// unable to parse the Disco payload
		return
	}

	e.handleDiscoControlMsg(from, senderIndex, discoMsg, uw, serverDisco)
}

type udpWriter interface {
	WriteMsgUDPAddrPort(b []byte, oob []byte, addr netip.AddrPort) (n, oobn int, err error)
}

func (e *serverEndpoint) handlePacket(from netip.AddrPort, gh packet.GeneveHeader, b []byte, uw udpWriter, serverDisco key.DiscoPublic) {
	if !gh.Control {
		if !e.isBound() {
			// not a control packet, but serverEndpoint isn't bound
			return
		}
		var to netip.AddrPort
		switch {
		case from == e.addrPorts[0]:
			e.lastSeen[0] = time.Now()
			to = e.addrPorts[1]
		case from == e.addrPorts[1]:
			e.lastSeen[1] = time.Now()
			to = e.addrPorts[0]
		default:
			// unrecognized source
			return
		}
		// relay packet
		uw.WriteMsgUDPAddrPort(b, nil, to)
		return
	}

	if e.isBound() {
		// control packet, but serverEndpoint is already bound
		return
	}

	if gh.Protocol != packet.GeneveProtocolDisco {
		// control packet, but not Disco
		return
	}

	msg := b[packet.GeneveFixedHeaderLength:]
	e.handleSealedDiscoControlMsg(from, msg, uw, serverDisco)
}

func (e *serverEndpoint) isExpired(now time.Time, bindLifetime, steadyStateLifetime time.Duration) bool {
	if !e.isBound() {
		if now.Sub(e.allocatedAt) > bindLifetime {
			return true
		}
		return false
	}
	if now.Sub(e.lastSeen[0]) > steadyStateLifetime || now.Sub(e.lastSeen[1]) > steadyStateLifetime {
		return true
	}
	return false
}

// isBound returns true if both clients have completed their 3-way handshake,
// otherwise false.
func (e *serverEndpoint) isBound() bool {
	return e.handshakeState[0] == disco.BindUDPRelayHandshakeStateAnswerReceived &&
		e.handshakeState[1] == disco.BindUDPRelayHandshakeStateAnswerReceived
}

// NewServer constructs a [Server] listening on 0.0.0.0:'port'. IPv6 is not yet
// supported. Port may be 0, and what ultimately gets bound is returned as
// 'boundPort'. Supplied 'addrs' are joined with 'boundPort' and returned as
// [endpoint.ServerEndpoint.AddrPorts] in response to Server.AllocateEndpoint()
// requests.
//
// TODO: IPv6 support
// TODO: dynamic addrs:port discovery
func NewServer(port int, addrs []netip.Addr) (s *Server, boundPort int, err error) {
	s = &Server{
		disco:               key.NewDisco(),
		bindLifetime:        defaultBindLifetime,
		steadyStateLifetime: defaultSteadyStateLifetime,
		closeCh:             make(chan struct{}),
		byDisco:             make(map[pairOfDiscoPubKeys]*serverEndpoint),
		byVNI:               make(map[uint32]*serverEndpoint),
	}
	s.discoPublic = s.disco.Public()
	// TODO: instead of allocating 10s of MBs for the full pool, allocate
	// smaller chunks and increase as needed
	s.vniPool = make([]uint32, 0, 1<<24-1)
	for i := 1; i < 1<<24; i++ {
		s.vniPool = append(s.vniPool, uint32(i))
	}
	boundPort, err = s.listenOn(port)
	if err != nil {
		return nil, 0, err
	}
	addrPorts := make([]netip.AddrPort, 0, len(addrs))
	for _, addr := range addrs {
		addrPort, err := netip.ParseAddrPort(net.JoinHostPort(addr.String(), strconv.Itoa(boundPort)))
		if err != nil {
			return nil, 0, err
		}
		addrPorts = append(addrPorts, addrPort)
	}
	s.addrPorts = addrPorts
	s.wg.Add(2)
	go s.packetReadLoop()
	go s.endpointGCLoop()
	return s, boundPort, nil
}

func (s *Server) listenOn(port int) (int, error) {
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err != nil {
		return 0, err
	}
	// TODO: set IP_PKTINFO sockopt
	_, boundPortStr, err := net.SplitHostPort(uc.LocalAddr().String())
	if err != nil {
		s.uc.Close()
		return 0, err
	}
	boundPort, err := strconv.Atoi(boundPortStr)
	if err != nil {
		s.uc.Close()
		return 0, err
	}
	s.uc = uc
	return boundPort, nil
}

// Close closes the server.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.uc.Close()
		close(s.closeCh)
		s.wg.Wait()
		clear(s.byVNI)
		clear(s.byDisco)
		s.vniPool = nil
		s.closed = true
	})
	return nil
}

func (s *Server) endpointGCLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.bindLifetime)
	defer ticker.Stop()

	gc := func() {
		now := time.Now()
		// TODO: consider performance implications of scanning all endpoints and
		// holding s.mu for the duration. Keep it simple (and slow) for now.
		s.mu.Lock()
		defer s.mu.Unlock()
		for k, v := range s.byDisco {
			if v.isExpired(now, s.bindLifetime, s.steadyStateLifetime) {
				delete(s.byDisco, k)
				delete(s.byVNI, v.vni)
				s.vniPool = append(s.vniPool, v.vni)
			}
		}
	}

	for {
		select {
		case <-ticker.C:
			gc()
		case <-s.closeCh:
			return
		}
	}
}

func (s *Server) handlePacket(from netip.AddrPort, b []byte, uw udpWriter) {
	gh := packet.GeneveHeader{}
	err := gh.Decode(b)
	if err != nil {
		return
	}
	// TODO: consider performance implications of holding s.mu for the remainder
	// of this method, which does a bunch of disco/crypto work depending. Keep
	// it simple (and slow) for now.
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byVNI[gh.VNI]
	if !ok {
		// unknown VNI
		return
	}

	e.handlePacket(from, gh, b, uw, s.discoPublic)
}

func (s *Server) packetReadLoop() {
	defer func() {
		s.wg.Done()
		s.Close()
	}()
	b := make([]byte, 1<<16-1)
	for {
		// TODO: extract laddr from IP_PKTINFO for use in reply
		n, from, err := s.uc.ReadFromUDPAddrPort(b)
		if err != nil {
			return
		}
		s.handlePacket(from, b[:n], s.uc)
	}
}

var ErrServerClosed = errors.New("server closed")

// AllocateEndpoint allocates an [endpoint.ServerEndpoint] for the provided pair
// of [key.DiscoPublic]'s. If an allocation already exists for discoA and discoB
// it is returned without modification/reallocation. AllocateEndpoint returns
// [ErrServerClosed] if the server has been closed.
func (s *Server) AllocateEndpoint(discoA, discoB key.DiscoPublic) (endpoint.ServerEndpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return endpoint.ServerEndpoint{}, ErrServerClosed
	}

	if discoA.Compare(s.discoPublic) == 0 || discoB.Compare(s.discoPublic) == 0 {
		return endpoint.ServerEndpoint{}, fmt.Errorf("client disco equals server disco: %s", s.discoPublic.ShortString())
	}

	pair := newPairOfDiscoPubKeys(discoA, discoB)
	e, ok := s.byDisco[pair]
	if ok {
		// Return the existing allocation. Clients can resolve duplicate
		// [endpoint.ServerEndpoint]'s via [endpoint.ServerEndpoint.LamportID].
		//
		// TODO: consider ServerEndpoint.BindLifetime -= time.Now()-e.allocatedAt
		// to give the client a more accurate picture of the bind window.
		return endpoint.ServerEndpoint{
			ServerDisco:         s.discoPublic,
			AddrPorts:           s.addrPorts,
			VNI:                 e.vni,
			LamportID:           e.lamportID,
			BindLifetime:        tstime.GoDuration{Duration: s.bindLifetime},
			SteadyStateLifetime: tstime.GoDuration{Duration: s.steadyStateLifetime},
		}, nil
	}

	if len(s.vniPool) == 0 {
		return endpoint.ServerEndpoint{}, errors.New("VNI pool exhausted")
	}

	s.lamportID++
	e = &serverEndpoint{
		discoPubKeys: pair,
		lamportID:    s.lamportID,
		allocatedAt:  time.Now(),
	}
	e.discoSharedSecrets[0] = s.disco.Shared(e.discoPubKeys[0])
	e.discoSharedSecrets[1] = s.disco.Shared(e.discoPubKeys[1])
	e.vni, s.vniPool = s.vniPool[0], s.vniPool[1:]
	rand.Read(e.challenge[0][:])
	rand.Read(e.challenge[1][:])

	s.byDisco[pair] = e
	s.byVNI[e.vni] = e

	return endpoint.ServerEndpoint{
		ServerDisco:         s.discoPublic,
		AddrPorts:           s.addrPorts,
		VNI:                 e.vni,
		LamportID:           e.lamportID,
		BindLifetime:        tstime.GoDuration{Duration: s.bindLifetime},
		SteadyStateLifetime: tstime.GoDuration{Duration: s.steadyStateLifetime},
	}, nil
}
