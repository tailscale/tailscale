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
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"time"

	"go4.org/mem"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/net/ipv6"
	"tailscale.com/disco"
	"tailscale.com/net/batching"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/net/packet"
	"tailscale.com/net/sockopts"
	"tailscale.com/net/stun"
	"tailscale.com/net/udprelay/endpoint"
	"tailscale.com/net/udprelay/status"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
	"tailscale.com/types/views"
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
	uc4                 batching.Conn // always non-nil
	uc4Port             uint16        // always nonzero
	uc6                 batching.Conn // may be nil if IPv6 bind fails during initialization
	uc6Port             uint16        // may be zero if IPv6 bind fails during initialization
	closeOnce           sync.Once
	wg                  sync.WaitGroup
	closeCh             chan struct{}
	netChecker          *netcheck.Client

	mu                  sync.Mutex           // guards the following fields
	macSecrets          [][blake2s.Size]byte // [0] is most recent, max 2 elements
	macSecretRotatedAt  time.Time
	derpMap             *tailcfg.DERPMap
	onlyStaticAddrPorts bool                        // no dynamic addr port discovery when set
	staticAddrPorts     views.Slice[netip.AddrPort] // static ip:port pairs set with [Server.SetStaticAddrPorts]
	dynamicAddrPorts    []netip.AddrPort            // dynamically discovered ip:port pairs
	closed              bool
	lamportID           uint64
	nextVNI             uint32
	byVNI               map[uint32]*serverEndpoint
	byDisco             map[key.SortedPairOfDiscoPublic]*serverEndpoint
}

const macSecretRotationInterval = time.Minute * 2

const (
	minVNI           = uint32(1)
	maxVNI           = uint32(1<<24 - 1)
	totalPossibleVNI = maxVNI - minVNI + 1
)

// serverEndpoint contains Server-internal [endpoint.ServerEndpoint] state.
// serverEndpoint methods are not thread-safe.
type serverEndpoint struct {
	// discoPubKeys contains the key.DiscoPublic of the served clients. The
	// indexing of this array aligns with the following fields, e.g.
	// discoSharedSecrets[0] is the shared secret to use when sealing
	// Disco protocol messages for transmission towards discoPubKeys[0].
	discoPubKeys         key.SortedPairOfDiscoPublic
	discoSharedSecrets   [2]key.DiscoShared
	inProgressGeneration [2]uint32         // or zero if a handshake has never started, or has just completed
	boundAddrPorts       [2]netip.AddrPort // or zero value if a handshake has never completed for that relay leg
	lastSeen             [2]time.Time      // TODO(jwhited): consider using mono.Time
	packetsRx            [2]uint64         // num packets received from/sent by each client after they are bound
	bytesRx              [2]uint64         // num bytes received from/sent by each client after they are bound

	lamportID   uint64
	vni         uint32
	allocatedAt time.Time
}

func blakeMACFromBindMsg(blakeKey [blake2s.Size]byte, src netip.AddrPort, msg disco.BindUDPRelayEndpointCommon) ([blake2s.Size]byte, error) {
	input := make([]byte, 8, 4+4+32+18) // vni + generation + invited party disco key + addr:port
	binary.BigEndian.PutUint32(input[0:4], msg.VNI)
	binary.BigEndian.PutUint32(input[4:8], msg.Generation)
	input = msg.RemoteKey.AppendTo(input)
	input, err := src.AppendBinary(input)
	if err != nil {
		return [blake2s.Size]byte{}, err
	}
	h, err := blake2s.New256(blakeKey[:])
	if err != nil {
		return [blake2s.Size]byte{}, err
	}
	_, err = h.Write(input)
	if err != nil {
		return [blake2s.Size]byte{}, err
	}
	var out [blake2s.Size]byte
	h.Sum(out[:0])
	return out, nil
}

func (e *serverEndpoint) handleDiscoControlMsg(from netip.AddrPort, senderIndex int, discoMsg disco.Message, serverDisco key.DiscoPublic, macSecrets [][blake2s.Size]byte) (write []byte, to netip.AddrPort) {
	if senderIndex != 0 && senderIndex != 1 {
		return nil, netip.AddrPort{}
	}

	otherSender := 0
	if senderIndex == 0 {
		otherSender = 1
	}

	validateVNIAndRemoteKey := func(common disco.BindUDPRelayEndpointCommon) error {
		if common.VNI != e.vni {
			return errors.New("mismatching VNI")
		}
		if common.RemoteKey.Compare(e.discoPubKeys.Get()[otherSender]) != 0 {
			return errors.New("mismatching RemoteKey")
		}
		return nil
	}

	switch discoMsg := discoMsg.(type) {
	case *disco.BindUDPRelayEndpoint:
		err := validateVNIAndRemoteKey(discoMsg.BindUDPRelayEndpointCommon)
		if err != nil {
			// silently drop
			return nil, netip.AddrPort{}
		}
		if discoMsg.Generation == 0 {
			// Generation must be nonzero, silently drop
			return nil, netip.AddrPort{}
		}
		e.inProgressGeneration[senderIndex] = discoMsg.Generation
		m := new(disco.BindUDPRelayEndpointChallenge)
		m.VNI = e.vni
		m.Generation = discoMsg.Generation
		m.RemoteKey = e.discoPubKeys.Get()[otherSender]
		reply := make([]byte, packet.GeneveFixedHeaderLength, 512)
		gh := packet.GeneveHeader{Control: true, Protocol: packet.GeneveProtocolDisco}
		gh.VNI.Set(e.vni)
		err = gh.Encode(reply)
		if err != nil {
			return nil, netip.AddrPort{}
		}
		reply = append(reply, disco.Magic...)
		reply = serverDisco.AppendTo(reply)
		mac, err := blakeMACFromBindMsg(macSecrets[0], from, m.BindUDPRelayEndpointCommon)
		if err != nil {
			return nil, netip.AddrPort{}
		}
		m.Challenge = mac
		box := e.discoSharedSecrets[senderIndex].Seal(m.AppendMarshal(nil))
		reply = append(reply, box...)
		return reply, from
	case *disco.BindUDPRelayEndpointAnswer:
		err := validateVNIAndRemoteKey(discoMsg.BindUDPRelayEndpointCommon)
		if err != nil {
			// silently drop
			return nil, netip.AddrPort{}
		}
		generation := e.inProgressGeneration[senderIndex]
		if generation == 0 || // we have no in-progress handshake
			generation != discoMsg.Generation { // mismatching generation for the in-progress handshake
			// silently drop
			return nil, netip.AddrPort{}
		}
		for _, macSecret := range macSecrets {
			mac, err := blakeMACFromBindMsg(macSecret, from, discoMsg.BindUDPRelayEndpointCommon)
			if err != nil {
				// silently drop
				return nil, netip.AddrPort{}
			}
			// Speed is favored over constant-time comparison here. The sender is
			// already authenticated via disco.
			if bytes.Equal(mac[:], discoMsg.Challenge[:]) {
				// Handshake complete. Update the binding for this sender.
				e.boundAddrPorts[senderIndex] = from
				e.lastSeen[senderIndex] = time.Now()    // record last seen as bound time
				e.inProgressGeneration[senderIndex] = 0 // reset to zero, which indicates there is no in-progress handshake
				return nil, netip.AddrPort{}
			}
		}
		// MAC does not match, silently drop
		return nil, netip.AddrPort{}
	default:
		// unexpected message types, silently drop
		return nil, netip.AddrPort{}
	}
}

func (e *serverEndpoint) handleSealedDiscoControlMsg(from netip.AddrPort, b []byte, serverDisco key.DiscoPublic, macSecrets [][blake2s.Size]byte) (write []byte, to netip.AddrPort) {
	senderRaw, isDiscoMsg := disco.Source(b)
	if !isDiscoMsg {
		// Not a Disco message
		return nil, netip.AddrPort{}
	}
	sender := key.DiscoPublicFromRaw32(mem.B(senderRaw))
	senderIndex := -1
	switch {
	case sender.Compare(e.discoPubKeys.Get()[0]) == 0:
		senderIndex = 0
	case sender.Compare(e.discoPubKeys.Get()[1]) == 0:
		senderIndex = 1
	default:
		// unknown Disco public key
		return nil, netip.AddrPort{}
	}

	const headerLen = len(disco.Magic) + key.DiscoPublicRawLen
	discoPayload, ok := e.discoSharedSecrets[senderIndex].Open(b[headerLen:])
	if !ok {
		// unable to decrypt the Disco payload
		return nil, netip.AddrPort{}
	}

	discoMsg, err := disco.Parse(discoPayload)
	if err != nil {
		// unable to parse the Disco payload
		return nil, netip.AddrPort{}
	}

	return e.handleDiscoControlMsg(from, senderIndex, discoMsg, serverDisco, macSecrets)
}

func (e *serverEndpoint) handleDataPacket(from netip.AddrPort, b []byte, now time.Time) (write []byte, to netip.AddrPort) {
	if !e.isBound() {
		// not a control packet, but serverEndpoint isn't bound
		return nil, netip.AddrPort{}
	}
	switch {
	case from == e.boundAddrPorts[0]:
		e.lastSeen[0] = now
		e.packetsRx[0]++
		e.bytesRx[0] += uint64(len(b))
		return b, e.boundAddrPorts[1]
	case from == e.boundAddrPorts[1]:
		e.lastSeen[1] = now
		e.packetsRx[1]++
		e.bytesRx[1] += uint64(len(b))
		return b, e.boundAddrPorts[0]
	default:
		// unrecognized source
		return nil, netip.AddrPort{}
	}
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
// onlyStaticAddrPorts is true, then dynamic addr:port discovery will be
// disabled, and only addr:port's set via [Server.SetStaticAddrPorts] will be
// used.
func NewServer(logf logger.Logf, port int, onlyStaticAddrPorts bool) (s *Server, err error) {
	s = &Server{
		logf:                logf,
		disco:               key.NewDisco(),
		bindLifetime:        defaultBindLifetime,
		steadyStateLifetime: defaultSteadyStateLifetime,
		closeCh:             make(chan struct{}),
		onlyStaticAddrPorts: onlyStaticAddrPorts,
		byDisco:             make(map[key.SortedPairOfDiscoPublic]*serverEndpoint),
		nextVNI:             minVNI,
		byVNI:               make(map[uint32]*serverEndpoint),
	}
	s.discoPublic = s.disco.Public()

	// TODO(creachadair): Find a way to plumb this in during initialization.
	// As-written, messages published here will not be seen by other components
	// in a running client.
	bus := eventbus.New()
	s.bus = bus
	netMon, err := netmon.New(s.bus, logf)
	if err != nil {
		return nil, err
	}
	s.netChecker = &netcheck.Client{
		NetMon: netMon,
		Logf:   logger.WithPrefix(logf, "netcheck: "),
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

	if !s.onlyStaticAddrPorts {
		s.wg.Add(1)
		go s.addrDiscoveryLoop()
	}

	s.wg.Add(1)
	go s.packetReadLoop(s.uc4, s.uc6, true)
	if s.uc6 != nil {
		s.wg.Add(1)
		go s.packetReadLoop(s.uc6, s.uc4, false)
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

		dm := s.getDERPMap()
		if dm == nil {
			// We don't have a DERPMap which is required to dynamically
			// discover external addresses, but we can return the endpoints we
			// do have.
			return addrPorts.Slice(), nil
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
		// Add STUN-discovered endpoints with their observed ports.
		v4Addrs, v6Addrs := rep.GetGlobalAddrs()
		for _, addr := range v4Addrs {
			if addr.IsValid() {
				addrPorts.Add(addr)
			}
		}
		for _, addr := range v6Addrs {
			if addr.IsValid() {
				addrPorts.Add(addr)
			}
		}

		if len(v4Addrs) >= 1 && v4Addrs[0].IsValid() {
			// If they're behind a hard NAT and are using a fixed
			// port locally, assume they might've added a static
			// port mapping on their router to the same explicit
			// port that the relay is running with. Worst case
			// it's an invalid candidate mapping.
			if rep.MappingVariesByDestIP.EqualBool(true) && s.uc4Port != 0 {
				addrPorts.Add(netip.AddrPortFrom(v4Addrs[0].Addr(), s.uc4Port))
			}
		}
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
			s.dynamicAddrPorts = addrPorts
			s.mu.Unlock()
		case <-s.closeCh:
			return
		}
	}
}

// This is a compile-time assertion that [singlePacketConn] implements the
// [batching.Conn] interface.
var _ batching.Conn = (*singlePacketConn)(nil)

// singlePacketConn implements [batching.Conn] with single packet syscall
// operations.
type singlePacketConn struct {
	*net.UDPConn
}

func (c *singlePacketConn) ReadBatch(msgs []ipv6.Message, _ int) (int, error) {
	n, ap, err := c.UDPConn.ReadFromUDPAddrPort(msgs[0].Buffers[0])
	if err != nil {
		return 0, err
	}
	msgs[0].N = n
	msgs[0].Addr = net.UDPAddrFromAddrPort(netaddr.Unmap(ap))
	return 1, nil
}

func (c *singlePacketConn) WriteBatchTo(buffs [][]byte, addr netip.AddrPort, geneve packet.GeneveHeader, offset int) error {
	for _, buff := range buffs {
		if geneve.VNI.IsSet() {
			geneve.Encode(buff)
		} else {
			buff = buff[offset:]
		}
		_, err := c.UDPConn.WriteToUDPAddrPort(buff, addr)
		if err != nil {
			return err
		}
	}
	return nil
}

// UDP socket read/write buffer size (7MB). At the time of writing (2025-08-21)
// this value was heavily influenced by magicsock, with similar motivations for
// its increase relative to typical defaults, e.g. long fat networks and
// reducing packet loss around crypto/syscall-induced delay.
const socketBufferSize = 7 << 20

func trySetUDPSocketOptions(pconn nettype.PacketConn, logf logger.Logf) {
	directions := []sockopts.BufferDirection{sockopts.ReadDirection, sockopts.WriteDirection}
	for _, direction := range directions {
		errForce, errPortable := sockopts.SetBufferSize(pconn, direction, socketBufferSize)
		if errForce != nil {
			logf("[warning] failed to force-set UDP %v buffer size to %d: %v; using kernel default values (impacts throughput only)", direction, socketBufferSize, errForce)
		}
		if errPortable != nil {
			logf("failed to set UDP %v buffer size to %d: %v", direction, socketBufferSize, errPortable)
		}
	}

	err := sockopts.SetICMPErrImmunity(pconn)
	if err != nil {
		logf("failed to set ICMP error immunity: %v", err)
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
// deal with EDR software closing them. http://go/corp/30118. We could re-use
// [magicsock.RebindingConn], which would also remove the need for
// [singlePacketConn], as [magicsock.RebindingConn] also handles fallback to
// single packet syscall operations.
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
		trySetUDPSocketOptions(uc, s.logf)
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
		pc := batching.TryUpgradeToConn(uc, network, batching.IdealBatchSize)
		bc, ok := pc.(batching.Conn)
		if !ok {
			bc = &singlePacketConn{uc}
		}
		if network == "udp4" {
			s.uc4 = bc
			s.uc4Port = uint16(portUint)
		} else {
			s.uc6 = bc
			s.uc6Port = uint16(portUint)
		}
		s.logf("listening on %s:%d", network, portUint)
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

func (s *Server) handlePacket(from netip.AddrPort, b []byte) (write []byte, to netip.AddrPort) {
	if stun.Is(b) && b[1] == 0x01 {
		// A b[1] value of 0x01 (STUN method binding) is sufficiently
		// non-overlapping with the Geneve header where the LSB is always 0
		// (part of 6 "reserved" bits).
		s.netChecker.ReceiveSTUNPacket(b, from)
		return nil, netip.AddrPort{}
	}
	gh := packet.GeneveHeader{}
	err := gh.Decode(b)
	if err != nil {
		return nil, netip.AddrPort{}
	}
	// TODO: consider performance implications of holding s.mu for the remainder
	// of this method, which does a bunch of disco/crypto work depending. Keep
	// it simple (and slow) for now.
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byVNI[gh.VNI.Get()]
	if !ok {
		// unknown VNI
		return nil, netip.AddrPort{}
	}

	now := time.Now()
	if gh.Control {
		if gh.Protocol != packet.GeneveProtocolDisco {
			// control packet, but not Disco
			return nil, netip.AddrPort{}
		}
		msg := b[packet.GeneveFixedHeaderLength:]
		s.maybeRotateMACSecretLocked(now)
		return e.handleSealedDiscoControlMsg(from, msg, s.discoPublic, s.macSecrets)
	}
	return e.handleDataPacket(from, b, now)
}

func (s *Server) maybeRotateMACSecretLocked(now time.Time) {
	if !s.macSecretRotatedAt.IsZero() && now.Sub(s.macSecretRotatedAt) < macSecretRotationInterval {
		return
	}
	switch len(s.macSecrets) {
	case 0:
		s.macSecrets = make([][blake2s.Size]byte, 1, 2)
	case 1:
		s.macSecrets = append(s.macSecrets, [blake2s.Size]byte{})
		fallthrough
	case 2:
		s.macSecrets[1] = s.macSecrets[0]
	}
	rand.Read(s.macSecrets[0][:])
	s.macSecretRotatedAt = now
	return
}

func (s *Server) packetReadLoop(readFromSocket, otherSocket batching.Conn, readFromSocketIsIPv4 bool) {
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

	msgs := make([]ipv6.Message, batching.IdealBatchSize)
	for i := range msgs {
		msgs[i].OOB = make([]byte, batching.MinControlMessageSize())
		msgs[i].Buffers = make([][]byte, 1)
		msgs[i].Buffers[0] = make([]byte, 1<<16-1)
	}
	writeBuffsByDest := make(map[netip.AddrPort][][]byte, batching.IdealBatchSize)

	for {
		for i := range msgs {
			msgs[i] = ipv6.Message{Buffers: msgs[i].Buffers, OOB: msgs[i].OOB[:cap(msgs[i].OOB)]}
		}

		// TODO: extract laddr from IP_PKTINFO for use in reply
		// ReadBatch will split coalesced datagrams before returning, which
		// WriteBatchTo will re-coalesce further down. We _could_ be more
		// efficient and not split datagrams that belong to the same VNI if they
		// are non-control/handshake packets. We pay the memmove/memcopy
		// performance penalty for now in the interest of simple single packet
		// handlers.
		n, err := readFromSocket.ReadBatch(msgs, 0)
		if err != nil {
			s.logf("error reading from socket(%v): %v", readFromSocket.LocalAddr(), err)
			return
		}

		for _, msg := range msgs[:n] {
			if msg.N == 0 {
				continue
			}
			buf := msg.Buffers[0][:msg.N]
			from := msg.Addr.(*net.UDPAddr).AddrPort()
			write, to := s.handlePacket(from, buf)
			if !to.IsValid() {
				continue
			}
			if from.Addr().Is4() == to.Addr().Is4() || otherSocket != nil {
				buffs, ok := writeBuffsByDest[to]
				if !ok {
					buffs = make([][]byte, 0, batching.IdealBatchSize)
				}
				buffs = append(buffs, write)
				writeBuffsByDest[to] = buffs
			} else {
				// This is unexpected. We should never produce a packet to write
				// to the "other" socket if the other socket is nil/unbound.
				// [server.handlePacket] has to see a packet from a particular
				// address family at least once in order for it to return a
				// packet to write towards a dest for the same address family.
				s.logf("[unexpected] packet from: %v produced packet to: %v while otherSocket is nil", from, to)
			}
		}

		for dest, buffs := range writeBuffsByDest {
			// Write the packet batches via the socket associated with the
			// destination's address family. If source and destination address
			// families are matching we tx on the same socket the packet was
			// received, otherwise we use the "other" socket. [Server] makes no
			// use of dual-stack sockets.
			if dest.Addr().Is4() == readFromSocketIsIPv4 {
				readFromSocket.WriteBatchTo(buffs, dest, packet.GeneveHeader{}, 0)
			} else {
				otherSocket.WriteBatchTo(buffs, dest, packet.GeneveHeader{}, 0)
			}
			delete(writeBuffsByDest, dest)
		}
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

// getNextVNILocked returns the next available VNI. It implements the
// "Traditional BSD Port Selection Algorithm" from RFC6056. This algorithm does
// not attempt to obfuscate the selection, i.e. the selection is predictable.
// For now, we favor simplicity and reducing VNI re-use over more complex
// ephemeral port (VNI) selection algorithms.
func (s *Server) getNextVNILocked() (uint32, error) {
	for i := uint32(0); i < totalPossibleVNI; i++ {
		vni := s.nextVNI
		if vni == maxVNI {
			s.nextVNI = minVNI
		} else {
			s.nextVNI++
		}
		_, ok := s.byVNI[vni]
		if !ok {
			return vni, nil
		}
	}
	return 0, errors.New("VNI pool exhausted")
}

// getAllAddrPortsCopyLocked returns a copy of the combined
// [Server.staticAddrPorts] and [Server.dynamicAddrPorts] slices.
func (s *Server) getAllAddrPortsCopyLocked() []netip.AddrPort {
	addrPorts := make([]netip.AddrPort, 0, len(s.dynamicAddrPorts)+s.staticAddrPorts.Len())
	addrPorts = append(addrPorts, s.staticAddrPorts.AsSlice()...)
	addrPorts = append(addrPorts, slices.Clone(s.dynamicAddrPorts)...)
	return addrPorts
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

	if s.staticAddrPorts.Len() == 0 && len(s.dynamicAddrPorts) == 0 {
		return endpoint.ServerEndpoint{}, ErrServerNotReady{RetryAfter: endpoint.ServerRetryAfter}
	}

	if discoA.Compare(s.discoPublic) == 0 || discoB.Compare(s.discoPublic) == 0 {
		return endpoint.ServerEndpoint{}, fmt.Errorf("client disco equals server disco: %s", s.discoPublic.ShortString())
	}

	pair := key.NewSortedPairOfDiscoPublic(discoA, discoB)
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
			ClientDisco:         pair.Get(),
			AddrPorts:           s.getAllAddrPortsCopyLocked(),
			VNI:                 e.vni,
			LamportID:           e.lamportID,
			BindLifetime:        tstime.GoDuration{Duration: s.bindLifetime},
			SteadyStateLifetime: tstime.GoDuration{Duration: s.steadyStateLifetime},
		}, nil
	}

	vni, err := s.getNextVNILocked()
	if err != nil {
		return endpoint.ServerEndpoint{}, err
	}

	s.lamportID++
	e = &serverEndpoint{
		discoPubKeys: pair,
		lamportID:    s.lamportID,
		allocatedAt:  time.Now(),
		vni:          vni,
	}
	e.discoSharedSecrets[0] = s.disco.Shared(e.discoPubKeys.Get()[0])
	e.discoSharedSecrets[1] = s.disco.Shared(e.discoPubKeys.Get()[1])

	s.byDisco[pair] = e
	s.byVNI[e.vni] = e

	s.logf("allocated endpoint vni=%d lamportID=%d disco[0]=%v disco[1]=%v", e.vni, e.lamportID, pair.Get()[0].ShortString(), pair.Get()[1].ShortString())
	return endpoint.ServerEndpoint{
		ServerDisco:         s.discoPublic,
		ClientDisco:         pair.Get(),
		AddrPorts:           s.getAllAddrPortsCopyLocked(),
		VNI:                 e.vni,
		LamportID:           e.lamportID,
		BindLifetime:        tstime.GoDuration{Duration: s.bindLifetime},
		SteadyStateLifetime: tstime.GoDuration{Duration: s.steadyStateLifetime},
	}, nil
}

// extractClientInfo constructs a [status.ClientInfo] for one of the two peer
// relay clients involved in this session.
func extractClientInfo(idx int, ep *serverEndpoint) status.ClientInfo {
	if idx != 0 && idx != 1 {
		panic(fmt.Sprintf("idx passed to extractClientInfo() must be 0 or 1; got %d", idx))
	}

	return status.ClientInfo{
		Endpoint:   ep.boundAddrPorts[idx],
		ShortDisco: ep.discoPubKeys.Get()[idx].ShortString(),
		PacketsTx:  ep.packetsRx[idx],
		BytesTx:    ep.bytesRx[idx],
	}
}

// GetSessions returns a slice of peer relay session statuses, with each
// entry containing detailed info about the server and clients involved in
// each session. This information is intended for debugging/status UX, and
// should not be relied on for any purpose outside of that.
func (s *Server) GetSessions() []status.ServerSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	var sessions = make([]status.ServerSession, 0, len(s.byDisco))
	for _, se := range s.byDisco {
		c1 := extractClientInfo(0, se)
		c2 := extractClientInfo(1, se)
		sessions = append(sessions, status.ServerSession{
			VNI:     se.vni,
			Client1: c1,
			Client2: c2,
		})
	}
	return sessions
}

// SetDERPMapView sets the [tailcfg.DERPMapView] to use for future netcheck
// reports.
func (s *Server) SetDERPMapView(view tailcfg.DERPMapView) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !view.Valid() {
		s.derpMap = nil
		return
	}
	s.derpMap = view.AsStruct()
}

func (s *Server) getDERPMap() *tailcfg.DERPMap {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.derpMap
}

// SetStaticAddrPorts sets addr:port pairs the [Server] will advertise
// as candidates it is potentially reachable over, in combination with
// dynamically discovered pairs. This replaces any previously-provided static
// values.
func (s *Server) SetStaticAddrPorts(addrPorts views.Slice[netip.AddrPort]) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.staticAddrPorts = addrPorts
}
