// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package udprelay contains constructs for relaying Disco and WireGuard packets
// between Tailscale clients over UDP. This package is currently considered
// experimental.
package udprelay

import (
	"bytes"
	"context"
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
	"tailscale.com/client/local"
	"tailscale.com/disco"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/net/packet"
	"tailscale.com/net/stun"
	"tailscale.com/net/udprelay/endpoint"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/set"
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
	// The following fields are initialized once and never mutated.
	logf                logger.Logf
	disco               key.DiscoPrivate
	discoPublic         key.DiscoPublic
	bindLifetime        time.Duration
	steadyStateLifetime time.Duration
	bus                 *eventbus.Bus
	uc4                 *net.UDPConn // always non-nil
	uc4Port             uint16       // always nonzero
	uc6                 *net.UDPConn // may be nil if IPv6 bind fails during initialization
	uc6Port             uint16       // may be zero if IPv6 bind fails during initialization
	closeOnce           sync.Once
	wg                  sync.WaitGroup
	closeCh             chan struct{}
	netChecker          *netcheck.Client

	mu                sync.Mutex       // guards the following fields
	addrDiscoveryOnce bool             // addrDiscovery completed once (successfully or unsuccessfully)
	addrPorts         []netip.AddrPort // the ip:port pairs returned as candidate endpoints
	closed            bool
	lamportID         uint64
	vniPool           []uint32 // the pool of available VNIs
	byVNI             map[uint32]*serverEndpoint
	byDisco           map[pairOfDiscoPubKeys]*serverEndpoint
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
	discoPubKeys        pairOfDiscoPubKeys
	discoSharedSecrets  [2]key.DiscoShared
	handshakeGeneration [2]uint32         // or zero if a handshake has never started for that relay leg
	handshakeAddrPorts  [2]netip.AddrPort // or zero value if a handshake has never started for that relay leg
	boundAddrPorts      [2]netip.AddrPort // or zero value if a handshake has never completed for that relay leg
	lastSeen            [2]time.Time      // TODO(jwhited): consider using mono.Time
	challenge           [2][disco.BindUDPRelayChallengeLen]byte

	lamportID   uint64
	vni         uint32
	allocatedAt time.Time
}

func (e *serverEndpoint) handleDiscoControlMsg(from netip.AddrPort, senderIndex int, discoMsg disco.Message, conn *net.UDPConn, serverDisco key.DiscoPublic) {
	if senderIndex != 0 && senderIndex != 1 {
		return
	}

	otherSender := 0
	if senderIndex == 0 {
		otherSender = 1
	}

	validateVNIAndRemoteKey := func(common disco.BindUDPRelayEndpointCommon) error {
		if common.VNI != e.vni {
			return errors.New("mismatching VNI")
		}
		if common.RemoteKey.Compare(e.discoPubKeys[otherSender]) != 0 {
			return errors.New("mismatching RemoteKey")
		}
		return nil
	}

	switch discoMsg := discoMsg.(type) {
	case *disco.BindUDPRelayEndpoint:
		err := validateVNIAndRemoteKey(discoMsg.BindUDPRelayEndpointCommon)
		if err != nil {
			// silently drop
			return
		}
		if discoMsg.Generation == 0 {
			// Generation must be nonzero, silently drop
			return
		}
		if e.handshakeGeneration[senderIndex] == discoMsg.Generation {
			// we've seen this generation before, silently drop
			return
		}
		e.handshakeGeneration[senderIndex] = discoMsg.Generation
		e.handshakeAddrPorts[senderIndex] = from
		m := new(disco.BindUDPRelayEndpointChallenge)
		m.VNI = e.vni
		m.Generation = discoMsg.Generation
		m.RemoteKey = e.discoPubKeys[otherSender]
		rand.Read(e.challenge[senderIndex][:])
		copy(m.Challenge[:], e.challenge[senderIndex][:])
		reply := make([]byte, packet.GeneveFixedHeaderLength, 512)
		gh := packet.GeneveHeader{Control: true, VNI: e.vni, Protocol: packet.GeneveProtocolDisco}
		err = gh.Encode(reply)
		if err != nil {
			return
		}
		reply = append(reply, disco.Magic...)
		reply = serverDisco.AppendTo(reply)
		box := e.discoSharedSecrets[senderIndex].Seal(m.AppendMarshal(nil))
		reply = append(reply, box...)
		conn.WriteMsgUDPAddrPort(reply, nil, from)
		return
	case *disco.BindUDPRelayEndpointAnswer:
		err := validateVNIAndRemoteKey(discoMsg.BindUDPRelayEndpointCommon)
		if err != nil {
			// silently drop
			return
		}
		generation := e.handshakeGeneration[senderIndex]
		if generation == 0 || // we have no active handshake
			generation != discoMsg.Generation || // mismatching generation for the active handshake
			e.handshakeAddrPorts[senderIndex] != from || // mismatching source for the active handshake
			!bytes.Equal(e.challenge[senderIndex][:], discoMsg.Challenge[:]) { // mismatching answer for the active handshake
			// silently drop
			return
		}
		// Handshake complete. Update the binding for this sender.
		e.boundAddrPorts[senderIndex] = from
		e.lastSeen[senderIndex] = time.Now() // record last seen as bound time
		return
	default:
		// unexpected message types, silently drop
		return
	}
}

func (e *serverEndpoint) handleSealedDiscoControlMsg(from netip.AddrPort, b []byte, conn *net.UDPConn, serverDisco key.DiscoPublic) {
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

	e.handleDiscoControlMsg(from, senderIndex, discoMsg, conn, serverDisco)
}

func (e *serverEndpoint) handlePacket(from netip.AddrPort, gh packet.GeneveHeader, b []byte, rxSocket, otherAFSocket *net.UDPConn, serverDisco key.DiscoPublic) {
	if !gh.Control {
		if !e.isBound() {
			// not a control packet, but serverEndpoint isn't bound
			return
		}
		var to netip.AddrPort
		switch {
		case from == e.boundAddrPorts[0]:
			e.lastSeen[0] = time.Now()
			to = e.boundAddrPorts[1]
		case from == e.boundAddrPorts[1]:
			e.lastSeen[1] = time.Now()
			to = e.boundAddrPorts[0]
		default:
			// unrecognized source
			return
		}
		// Relay the packet towards the other party via the socket associated
		// with the destination's address family. If source and destination
		// address families are matching we tx on the same socket the packet
		// was received (rxSocket), otherwise we use the "other" socket
		// (otherAFSocket). [Server] makes no use of dual-stack sockets.
		if from.Addr().Is4() == to.Addr().Is4() {
			rxSocket.WriteMsgUDPAddrPort(b, nil, to)
		} else if otherAFSocket != nil {
			otherAFSocket.WriteMsgUDPAddrPort(b, nil, to)
		}
		return
	}

	if gh.Protocol != packet.GeneveProtocolDisco {
		// control packet, but not Disco
		return
	}

	msg := b[packet.GeneveFixedHeaderLength:]
	e.handleSealedDiscoControlMsg(from, msg, rxSocket, serverDisco)
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

// isBound returns true if both clients have completed a 3-way handshake,
// otherwise false.
func (e *serverEndpoint) isBound() bool {
	return e.boundAddrPorts[0].IsValid() &&
		e.boundAddrPorts[1].IsValid()
}

// NewServer constructs a [Server] listening on port. If port is zero, then
// port selection is left up to the host networking stack. If
// len(overrideAddrs) > 0 these will be used in place of dynamic discovery,
// which is useful to override in tests.
func NewServer(logf logger.Logf, port int, overrideAddrs []netip.Addr) (s *Server, err error) {
	s = &Server{
		logf:                logger.WithPrefix(logf, "relayserver"),
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

	bus := eventbus.New()
	s.bus = bus
	netMon, err := netmon.New(s.bus, logf)
	if err != nil {
		return nil, err
	}
	s.netChecker = &netcheck.Client{
		NetMon: netMon,
		Logf:   logger.WithPrefix(logf, "relayserver: netcheck:"),
		SendPacket: func(b []byte, addrPort netip.AddrPort) (int, error) {
			if addrPort.Addr().Is4() {
				return s.uc4.WriteToUDPAddrPort(b, addrPort)
			} else if s.uc6 != nil {
				return s.uc6.WriteToUDPAddrPort(b, addrPort)
			} else {
				return 0, errors.New("IPv6 socket is not bound")
			}
		},
	}

	err = s.listenOn(port)
	if err != nil {
		return nil, err
	}

	if len(overrideAddrs) > 0 {
		addrPorts := make(set.Set[netip.AddrPort], len(overrideAddrs))
		for _, addr := range overrideAddrs {
			if addr.IsValid() {
				if addr.Is4() {
					addrPorts.Add(netip.AddrPortFrom(addr, s.uc4Port))
				} else if s.uc6 != nil {
					addrPorts.Add(netip.AddrPortFrom(addr, s.uc6Port))
				}
			}
		}
		s.addrPorts = addrPorts.Slice()
	} else {
		s.wg.Add(1)
		go s.addrDiscoveryLoop()
	}

	s.wg.Add(1)
	go s.packetReadLoop(s.uc4, s.uc6)
	if s.uc6 != nil {
		s.wg.Add(1)
		go s.packetReadLoop(s.uc6, s.uc4)
	}
	s.wg.Add(1)
	go s.endpointGCLoop()

	return s, nil
}

func (s *Server) addrDiscoveryLoop() {
	defer s.wg.Done()

	timer := time.NewTimer(0) // fire immediately
	defer timer.Stop()

	getAddrPorts := func() ([]netip.AddrPort, error) {
		var addrPorts set.Set[netip.AddrPort]
		addrPorts.Make()

		// get local addresses
		ips, _, err := netmon.LocalAddresses()
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if ip.IsValid() {
				if ip.Is4() {
					addrPorts.Add(netip.AddrPortFrom(ip, s.uc4Port))
				} else {
					addrPorts.Add(netip.AddrPortFrom(ip, s.uc6Port))
				}
			}
		}

		// fetch DERPMap to feed to netcheck
		derpMapCtx, derpMapCancel := context.WithTimeout(context.Background(), time.Second)
		defer derpMapCancel()
		localClient := &local.Client{}
		// TODO(jwhited): We are in-process so use eventbus or similar.
		//  local.Client gets us going.
		dm, err := localClient.CurrentDERPMap(derpMapCtx)
		if err != nil {
			return nil, err
		}

		// get addrPorts as visible from DERP
		netCheckerCtx, netCheckerCancel := context.WithTimeout(context.Background(), netcheck.ReportTimeout)
		defer netCheckerCancel()
		rep, err := s.netChecker.GetReport(netCheckerCtx, dm, &netcheck.GetReportOpts{
			OnlySTUN: true,
		})
		if err != nil {
			return nil, err
		}
		if rep.GlobalV4.IsValid() {
			addrPorts.Add(rep.GlobalV4)
		}
		if rep.GlobalV6.IsValid() {
			addrPorts.Add(rep.GlobalV6)
		}
		// TODO(jwhited): consider logging if rep.MappingVariesByDestIP as
		//  that's a hint we are not well-positioned to operate as a UDP relay.
		return addrPorts.Slice(), nil
	}

	for {
		select {
		case <-timer.C:
			// Mirror magicsock behavior for duration between STUN. We consider
			// 30s a min bound for NAT timeout.
			timer.Reset(tstime.RandomDurationBetween(20*time.Second, 26*time.Second))
			addrPorts, err := getAddrPorts()
			if err != nil {
				s.logf("error discovering IP:port candidates: %v", err)
			}
			s.mu.Lock()
			s.addrPorts = addrPorts
			s.addrDiscoveryOnce = true
			s.mu.Unlock()
		case <-s.closeCh:
			return
		}
	}
}

// listenOn binds an IPv4 and IPv6 socket to port. We consider it successful if
// we manage to bind the IPv4 socket.
//
// The requested port may be zero, in which case port selection is left up to
// the host networking stack. We make no attempt to bind a consistent port
// across IPv4 and IPv6 if the requested port is zero.
//
// TODO: make these "re-bindable" in similar fashion to magicsock as a means to
// deal with EDR software closing them. http://go/corp/30118
func (s *Server) listenOn(port int) error {
	for _, network := range []string{"udp4", "udp6"} {
		uc, err := net.ListenUDP(network, &net.UDPAddr{Port: port})
		if err != nil {
			if network == "udp4" {
				return err
			} else {
				s.logf("ignoring IPv6 bind failure: %v", err)
				break
			}
		}
		// TODO: set IP_PKTINFO sockopt
		_, boundPortStr, err := net.SplitHostPort(uc.LocalAddr().String())
		if err != nil {
			uc.Close()
			if s.uc4 != nil {
				s.uc4.Close()
			}
			return err
		}
		portUint, err := strconv.ParseUint(boundPortStr, 10, 16)
		if err != nil {
			uc.Close()
			if s.uc4 != nil {
				s.uc4.Close()
			}
			return err
		}
		if network == "udp4" {
			s.uc4 = uc
			s.uc4Port = uint16(portUint)
		} else {
			s.uc6 = uc
			s.uc6Port = uint16(portUint)
		}
	}
	return nil
}

// Close closes the server.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.uc4.Close()
		if s.uc6 != nil {
			s.uc6.Close()
		}
		close(s.closeCh)
		s.wg.Wait()
		// s.mu must not be held while s.wg.Wait'ing, otherwise we can
		// deadlock. The goroutines we are waiting on to return can also
		// acquire s.mu.
		s.mu.Lock()
		defer s.mu.Unlock()
		clear(s.byVNI)
		clear(s.byDisco)
		s.vniPool = nil
		s.closed = true
		s.bus.Close()
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

func (s *Server) handlePacket(from netip.AddrPort, b []byte, rxSocket, otherAFSocket *net.UDPConn) {
	if stun.Is(b) && b[1] == 0x01 {
		// A b[1] value of 0x01 (STUN method binding) is sufficiently
		// non-overlapping with the Geneve header where the LSB is always 0
		// (part of 6 "reserved" bits).
		s.netChecker.ReceiveSTUNPacket(b, from)
		return
	}
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

	e.handlePacket(from, gh, b, rxSocket, otherAFSocket, s.discoPublic)
}

func (s *Server) packetReadLoop(readFromSocket, otherSocket *net.UDPConn) {
	defer func() {
		// We intentionally close the [Server] if we encounter a socket read
		// error below, at least until socket "re-binding" is implemented as
		// part of http://go/corp/30118.
		//
		// Decrementing this [sync.WaitGroup] _before_ calling [Server.Close] is
		// intentional as [Server.Close] waits on it.
		s.wg.Done()
		s.Close()
	}()
	b := make([]byte, 1<<16-1)
	for {
		// TODO: extract laddr from IP_PKTINFO for use in reply
		n, from, err := readFromSocket.ReadFromUDPAddrPort(b)
		if err != nil {
			s.logf("error reading from socket(%v): %v", readFromSocket.LocalAddr(), err)
			return
		}
		s.handlePacket(from, b[:n], readFromSocket, otherSocket)
	}
}

var ErrServerClosed = errors.New("server closed")

// ErrServerNotReady indicates the server is not ready. Allocation should be
// requested after waiting for at least RetryAfter duration.
type ErrServerNotReady struct {
	RetryAfter time.Duration
}

func (e ErrServerNotReady) Error() string {
	return fmt.Sprintf("server not ready, retry after %v", e.RetryAfter)
}

// AllocateEndpoint allocates an [endpoint.ServerEndpoint] for the provided pair
// of [key.DiscoPublic]'s. If an allocation already exists for discoA and discoB
// it is returned without modification/reallocation. AllocateEndpoint returns
// the following notable errors:
//  1. [ErrServerClosed] if the server has been closed.
//  2. [ErrServerNotReady] if the server is not ready.
func (s *Server) AllocateEndpoint(discoA, discoB key.DiscoPublic) (endpoint.ServerEndpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return endpoint.ServerEndpoint{}, ErrServerClosed
	}

	if len(s.addrPorts) == 0 {
		if !s.addrDiscoveryOnce {
			return endpoint.ServerEndpoint{}, ErrServerNotReady{RetryAfter: 3 * time.Second}
		}
		return endpoint.ServerEndpoint{}, errors.New("server addrPorts are not yet known")
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
			ServerDisco: s.discoPublic,
			// Returning the "latest" addrPorts for an existing allocation is
			// the simple choice. It may not be the best depending on client
			// behaviors and endpoint state (bound or not). We might want to
			// consider storing them (maybe interning) in the [*serverEndpoint]
			// at allocation time.
			AddrPorts:           slices.Clone(s.addrPorts),
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

	s.byDisco[pair] = e
	s.byVNI[e.vni] = e

	return endpoint.ServerEndpoint{
		ServerDisco:         s.discoPublic,
		AddrPorts:           slices.Clone(s.addrPorts),
		VNI:                 e.vni,
		LamportID:           e.lamportID,
		BindLifetime:        tstime.GoDuration{Duration: s.bindLifetime},
		SteadyStateLifetime: tstime.GoDuration{Duration: s.steadyStateLifetime},
	}, nil
}
