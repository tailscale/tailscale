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
	"runtime"
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
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
	"tailscale.com/types/views"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/set"
	"tailscale.com/util/usermetric"
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
	uc4                 []batching.Conn // length is always nonzero
	uc4Port             uint16          // always nonzero
	uc6                 []batching.Conn // length may be zero if udp6 bind fails
	uc6Port             uint16          // zero if len(uc6) is zero, otherwise nonzero
	closeOnce           sync.Once
	wg                  sync.WaitGroup
	closeCh             chan struct{}
	netChecker          *netcheck.Client
	metrics             *metrics

	mu                  sync.Mutex                      // guards the following fields
	macSecrets          views.Slice[[blake2s.Size]byte] // [0] is most recent, max 2 elements
	macSecretRotatedAt  mono.Time
	derpMap             *tailcfg.DERPMap
	onlyStaticAddrPorts bool                        // no dynamic addr port discovery when set
	staticAddrPorts     views.Slice[netip.AddrPort] // static ip:port pairs set with [Server.SetStaticAddrPorts]
	dynamicAddrPorts    []netip.AddrPort            // dynamically discovered ip:port pairs
	closed              bool
	lamportID           uint64
	nextVNI             uint32
	// serverEndpointByVNI is consistent with serverEndpointByDisco while mu is
	// held, i.e. mu must be held around write ops. Read ops in performance
	// sensitive paths, e.g. packet forwarding, do not need to acquire mu.
	serverEndpointByVNI   sync.Map // key is uint32 (Geneve VNI), value is [*serverEndpoint]
	serverEndpointByDisco map[key.SortedPairOfDiscoPublic]*serverEndpoint
}

const macSecretRotationInterval = time.Minute * 2

const (
	minVNI           = uint32(1)
	maxVNI           = uint32(1<<24 - 1)
	totalPossibleVNI = maxVNI - minVNI + 1
)

// serverEndpoint contains Server-internal [endpoint.ServerEndpoint] state.
type serverEndpoint struct {
	// discoPubKeys contains the key.DiscoPublic of the served clients. The
	// indexing of this array aligns with the following fields, e.g.
	// discoSharedSecrets[0] is the shared secret to use when sealing
	// Disco protocol messages for transmission towards discoPubKeys[0].
	discoPubKeys       key.SortedPairOfDiscoPublic
	discoSharedSecrets [2]key.DiscoShared
	lamportID          uint64
	vni                uint32
	allocatedAt        mono.Time

	mu                   sync.Mutex        // guards the following fields
	inProgressGeneration [2]uint32         // or zero if a handshake has never started, or has just completed
	boundAddrPorts       [2]netip.AddrPort // or zero value if a handshake has never completed for that relay leg
	lastSeen             [2]mono.Time
	packetsRx            [2]uint64 // num packets received from/sent by each client after they are bound
	bytesRx              [2]uint64 // num bytes received from/sent by each client after they are bound
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

func (e *serverEndpoint) handleDiscoControlMsg(from netip.AddrPort, senderIndex int, discoMsg disco.Message, serverDisco key.DiscoPublic, macSecrets views.Slice[[blake2s.Size]byte], now mono.Time) (write []byte, to netip.AddrPort) {
	e.mu.Lock()
	defer e.mu.Unlock()

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
		mac, err := blakeMACFromBindMsg(macSecrets.At(0), from, m.BindUDPRelayEndpointCommon)
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
		for _, macSecret := range macSecrets.All() {
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
				e.lastSeen[senderIndex] = now           // record last seen as bound time
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

func (e *serverEndpoint) handleSealedDiscoControlMsg(from netip.AddrPort, b []byte, serverDisco key.DiscoPublic, macSecrets views.Slice[[blake2s.Size]byte], now mono.Time) (write []byte, to netip.AddrPort) {
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

	return e.handleDiscoControlMsg(from, senderIndex, discoMsg, serverDisco, macSecrets, now)
}

func (e *serverEndpoint) handleDataPacket(from netip.AddrPort, b []byte, now mono.Time) (write []byte, to netip.AddrPort) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.isBoundLocked() {
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

func (e *serverEndpoint) isExpired(now mono.Time, bindLifetime, steadyStateLifetime time.Duration) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.isBoundLocked() {
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

// isBoundLocked returns true if both clients have completed a 3-way handshake,
// otherwise false.
func (e *serverEndpoint) isBoundLocked() bool {
	return e.boundAddrPorts[0].IsValid() &&
		e.boundAddrPorts[1].IsValid()
}

// NewServer constructs a [Server] listening on port. If port is zero, then
// port selection is left up to the host networking stack. If
// onlyStaticAddrPorts is true, then dynamic addr:port discovery will be
// disabled, and only addr:port's set via [Server.SetStaticAddrPorts] will be
// used. Metrics must be non-nil.
func NewServer(logf logger.Logf, port uint16, onlyStaticAddrPorts bool, metrics *usermetric.Registry) (s *Server, err error) {
	s = &Server{
		logf:                  logf,
		disco:                 key.NewDisco(),
		bindLifetime:          defaultBindLifetime,
		steadyStateLifetime:   defaultSteadyStateLifetime,
		closeCh:               make(chan struct{}),
		onlyStaticAddrPorts:   onlyStaticAddrPorts,
		serverEndpointByDisco: make(map[key.SortedPairOfDiscoPublic]*serverEndpoint),
		nextVNI:               minVNI,
	}
	s.discoPublic = s.disco.Public()
	s.metrics = registerMetrics(metrics)

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
				return s.uc4[0].WriteToUDPAddrPort(b, addrPort)
			} else if len(s.uc6) > 0 {
				return s.uc6[0].WriteToUDPAddrPort(b, addrPort)
			} else {
				return 0, errors.New("IPv6 socket is not bound")
			}
		},
	}

	err = s.bindSockets(port)
	if err != nil {
		return nil, err
	}
	s.startPacketReaders()

	if !s.onlyStaticAddrPorts {
		s.wg.Add(1)
		go s.addrDiscoveryLoop()
	}

	s.wg.Add(1)
	go s.endpointGCLoop()

	return s, nil
}

func (s *Server) startPacketReaders() {
	for i, uc := range s.uc4 {
		var other batching.Conn
		if len(s.uc6) > 0 {
			other = s.uc6[min(len(s.uc6)-1, i)]
		}
		s.wg.Add(1)
		go s.packetReadLoop(uc, other, true)
	}
	for i, uc := range s.uc6 {
		var other batching.Conn
		if len(s.uc4) > 0 {
			other = s.uc4[min(len(s.uc4)-1, i)]
		}
		s.wg.Add(1)
		go s.packetReadLoop(uc, other, false)
	}
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

// bindSockets binds udp4 and udp6 sockets to desiredPort. We consider it
// successful if we manage to bind at least one udp4 socket. Multiple sockets
// may be bound per address family, e.g. SO_REUSEPORT, depending on platform.
//
// desiredPort may be zero, in which case port selection is left up to the host
// networking stack. We make no attempt to bind a consistent port between udp4
// and udp6 if the requested port is zero, but a consistent port is used
// across multiple sockets within a given address family if SO_REUSEPORT is
// supported.
//
// TODO: make these "re-bindable" in similar fashion to magicsock as a means to
// deal with EDR software closing them. http://go/corp/30118. We could re-use
// [magicsock.RebindingConn], which would also remove the need for
// [singlePacketConn], as [magicsock.RebindingConn] also handles fallback to
// single packet syscall operations.
func (s *Server) bindSockets(desiredPort uint16) error {
	// maxSocketsPerAF is a conservative starting point, but is somewhat
	// arbitrary.
	maxSocketsPerAF := min(16, runtime.NumCPU())
	listenConfig := &net.ListenConfig{
		Control: listenControl,
	}
	for _, network := range []string{"udp4", "udp6"} {
	SocketsLoop:
		for i := range maxSocketsPerAF {
			if i > 0 {
				// Use a consistent port per address family if the user-supplied
				// port was zero, and we are binding multiple sockets.
				if network == "udp4" {
					desiredPort = s.uc4Port
				} else {
					desiredPort = s.uc6Port
				}
			}
			uc, boundPort, err := s.bindSocketTo(listenConfig, network, desiredPort)
			if err != nil {
				switch {
				case i == 0 && network == "udp4":
					// At least one udp4 socket is required.
					return err
				case i == 0 && network == "udp6":
					// A udp6 socket is not required.
					s.logf("ignoring IPv6 bind failure: %v", err)
					break SocketsLoop
				default: // i > 0
					// Reusable sockets are not required.
					s.logf("ignoring reusable (index=%d network=%v) socket bind failure: %v", i, network, err)
					break SocketsLoop
				}
			}
			pc := batching.TryUpgradeToConn(uc, network, batching.IdealBatchSize)
			bc, ok := pc.(batching.Conn)
			if !ok {
				bc = &singlePacketConn{uc}
			}
			if network == "udp4" {
				s.uc4 = append(s.uc4, bc)
				s.uc4Port = boundPort
			} else {
				s.uc6 = append(s.uc6, bc)
				s.uc6Port = boundPort
			}
			if !isReusableSocket(uc) {
				break
			}
		}
	}
	s.logf("listening on udp4:%d sockets=%d", s.uc4Port, len(s.uc4))
	if len(s.uc6) > 0 {
		s.logf("listening on udp6:%d sockets=%d", s.uc6Port, len(s.uc6))
	}
	return nil
}

func (s *Server) bindSocketTo(listenConfig *net.ListenConfig, network string, port uint16) (*net.UDPConn, uint16, error) {
	lis, err := listenConfig.ListenPacket(context.Background(), network, fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, 0, err
	}
	uc := lis.(*net.UDPConn)
	trySetUDPSocketOptions(uc, s.logf)
	_, boundPortStr, err := net.SplitHostPort(uc.LocalAddr().String())
	if err != nil {
		uc.Close()
		return nil, 0, err
	}
	portUint, err := strconv.ParseUint(boundPortStr, 10, 16)
	if err != nil {
		uc.Close()
		return nil, 0, err
	}
	return uc, uint16(portUint), nil
}

// Close closes the server.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		for _, uc4 := range s.uc4 {
			uc4.Close()
		}
		for _, uc6 := range s.uc6 {
			uc6.Close()
		}
		close(s.closeCh)
		s.wg.Wait()
		// s.mu must not be held while s.wg.Wait'ing, otherwise we can
		// deadlock. The goroutines we are waiting on to return can also
		// acquire s.mu.
		s.mu.Lock()
		defer s.mu.Unlock()
		s.serverEndpointByVNI.Clear()
		clear(s.serverEndpointByDisco)
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
		now := mono.Now()
		// TODO: consider performance implications of scanning all endpoints and
		// holding s.mu for the duration. Keep it simple (and slow) for now.
		s.mu.Lock()
		defer s.mu.Unlock()
		for k, v := range s.serverEndpointByDisco {
			if v.isExpired(now, s.bindLifetime, s.steadyStateLifetime) {
				s.metrics.addEndpoints(-1)
				delete(s.serverEndpointByDisco, k)
				s.serverEndpointByVNI.Delete(v.vni)
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

// handlePacket unwraps headers and dispatches packet handling according to its
// type and destination. If the returned address is valid, write will contain data
// to transmit, and isDataPacket signals whether input was a data packet or OOB
// signaling.
//
//		write, to, isDataPacket := s.handlePacket(from, buf)
//		if to.IsValid() && isDataPacket {
//			// ..handle data transmission
//		}

func (s *Server) handlePacket(from netip.AddrPort, b []byte) (write []byte, to netip.AddrPort, isDataPacket bool) {
	if stun.Is(b) && b[1] == 0x01 {
		// A b[1] value of 0x01 (STUN method binding) is sufficiently
		// non-overlapping with the Geneve header where the LSB is always 0
		// (part of 6 "reserved" bits).
		s.netChecker.ReceiveSTUNPacket(b, from)
		return nil, netip.AddrPort{}, false
	}
	gh := packet.GeneveHeader{}
	err := gh.Decode(b)
	if err != nil {
		return nil, netip.AddrPort{}, false
	}
	e, ok := s.serverEndpointByVNI.Load(gh.VNI.Get())
	if !ok {
		// unknown VNI
		return nil, netip.AddrPort{}, false
	}

	now := mono.Now()
	if gh.Control {
		if gh.Protocol != packet.GeneveProtocolDisco {
			// control packet, but not Disco
			return nil, netip.AddrPort{}, false
		}
		msg := b[packet.GeneveFixedHeaderLength:]
		secrets := s.getMACSecrets(now)
		write, to = e.(*serverEndpoint).handleSealedDiscoControlMsg(from, msg, s.discoPublic, secrets, now)
		isDataPacket = false
		return
	}
	write, to = e.(*serverEndpoint).handleDataPacket(from, b, now)
	isDataPacket = true
	return
}

func (s *Server) getMACSecrets(now mono.Time) views.Slice[[blake2s.Size]byte] {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeRotateMACSecretLocked(now)
	return s.macSecrets
}

func (s *Server) maybeRotateMACSecretLocked(now mono.Time) {
	if !s.macSecretRotatedAt.IsZero() && now.Sub(s.macSecretRotatedAt) < macSecretRotationInterval {
		return
	}
	secrets := s.macSecrets.AsSlice()
	switch len(secrets) {
	case 0:
		secrets = make([][blake2s.Size]byte, 1, 2)
	case 1:
		secrets = append(secrets, [blake2s.Size]byte{})
		fallthrough
	case 2:
		secrets[1] = secrets[0]
	}
	rand.Read(secrets[0][:])
	s.macSecretRotatedAt = now
	s.macSecrets = views.SliceOf(secrets)
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

		// Aggregate counts for the packet batch before writing metrics.
		forwardedByOutAF := struct {
			bytes4   int64
			packets4 int64
			bytes6   int64
			packets6 int64
		}{}
		for _, msg := range msgs[:n] {
			if msg.N == 0 {
				continue
			}
			buf := msg.Buffers[0][:msg.N]
			from := msg.Addr.(*net.UDPAddr).AddrPort()
			write, to, isDataPacket := s.handlePacket(from, buf)
			if !to.IsValid() {
				continue
			}
			if isDataPacket {
				if to.Addr().Is4() {
					forwardedByOutAF.bytes4 += int64(len(write))
					forwardedByOutAF.packets4++
				} else {
					forwardedByOutAF.bytes6 += int64(len(write))
					forwardedByOutAF.packets6++
				}
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

		s.metrics.countForwarded(readFromSocketIsIPv4, true, forwardedByOutAF.bytes4, forwardedByOutAF.packets4)
		s.metrics.countForwarded(readFromSocketIsIPv4, false, forwardedByOutAF.bytes6, forwardedByOutAF.packets6)
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
		_, ok := s.serverEndpointByVNI.Load(vni)
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
	e, ok := s.serverEndpointByDisco[pair]
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
		allocatedAt:  mono.Now(),
		vni:          vni,
	}
	e.discoSharedSecrets[0] = s.disco.Shared(e.discoPubKeys.Get()[0])
	e.discoSharedSecrets[1] = s.disco.Shared(e.discoPubKeys.Get()[1])

	s.serverEndpointByDisco[pair] = e
	s.serverEndpointByVNI.Store(e.vni, e)

	s.logf("allocated endpoint vni=%d lamportID=%d disco[0]=%v disco[1]=%v", e.vni, e.lamportID, pair.Get()[0].ShortString(), pair.Get()[1].ShortString())
	s.metrics.addEndpoints(1)
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

// extractClientInfo constructs a [status.ClientInfo] for both relay clients
// involved in this session.
func (e *serverEndpoint) extractClientInfo() [2]status.ClientInfo {
	e.mu.Lock()
	defer e.mu.Unlock()
	ret := [2]status.ClientInfo{}
	for i := range e.boundAddrPorts {
		ret[i].Endpoint = e.boundAddrPorts[i]
		ret[i].ShortDisco = e.discoPubKeys.Get()[i].ShortString()
		ret[i].PacketsTx = e.packetsRx[i]
		ret[i].BytesTx = e.bytesRx[i]
	}
	return ret
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
	var sessions = make([]status.ServerSession, 0, len(s.serverEndpointByDisco))
	for _, se := range s.serverEndpointByDisco {
		clientInfos := se.extractClientInfo()
		sessions = append(sessions, status.ServerSession{
			VNI:     se.vni,
			Client1: clientInfos[0],
			Client2: clientInfos[1],
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
