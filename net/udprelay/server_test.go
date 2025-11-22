// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package udprelay

import (
	"bytes"
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go4.org/mem"
	"golang.org/x/crypto/blake2s"
	"tailscale.com/disco"
	"tailscale.com/net/packet"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

type testClient struct {
	vni                 uint32
	handshakeGeneration uint32
	local               key.DiscoPrivate
	remote              key.DiscoPublic
	server              key.DiscoPublic
	uc                  *net.UDPConn
}

func newTestClient(t *testing.T, vni uint32, serverEndpoint netip.AddrPort, local key.DiscoPrivate, remote, server key.DiscoPublic) *testClient {
	rAddr := &net.UDPAddr{IP: serverEndpoint.Addr().AsSlice(), Port: int(serverEndpoint.Port())}
	uc, err := net.DialUDP("udp", nil, rAddr)
	if err != nil {
		t.Fatal(err)
	}
	return &testClient{
		vni:                 vni,
		handshakeGeneration: 1,
		local:               local,
		remote:              remote,
		server:              server,
		uc:                  uc,
	}
}

func (c *testClient) write(t *testing.T, b []byte) {
	_, err := c.uc.Write(b)
	if err != nil {
		t.Fatal(err)
	}
}

func (c *testClient) read(t *testing.T) []byte {
	c.uc.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 1<<16-1)
	n, err := c.uc.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	return b[:n]
}

func (c *testClient) writeDataPkt(t *testing.T, b []byte) {
	pkt := make([]byte, packet.GeneveFixedHeaderLength, packet.GeneveFixedHeaderLength+len(b))
	gh := packet.GeneveHeader{Control: false, Protocol: packet.GeneveProtocolWireGuard}
	gh.VNI.Set(c.vni)
	err := gh.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	pkt = append(pkt, b...)
	c.write(t, pkt)
}

func (c *testClient) readDataPkt(t *testing.T) []byte {
	b := c.read(t)
	gh := packet.GeneveHeader{}
	err := gh.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if gh.Protocol != packet.GeneveProtocolWireGuard {
		t.Fatal("unexpected geneve protocol")
	}
	if gh.Control {
		t.Fatal("unexpected control")
	}
	if gh.VNI.Get() != c.vni {
		t.Fatal("unexpected vni")
	}
	return b[packet.GeneveFixedHeaderLength:]
}

func (c *testClient) writeControlDiscoMsg(t *testing.T, msg disco.Message) {
	pkt := make([]byte, packet.GeneveFixedHeaderLength, 512)
	gh := packet.GeneveHeader{Control: true, Protocol: packet.GeneveProtocolDisco}
	gh.VNI.Set(c.vni)
	err := gh.Encode(pkt)
	if err != nil {
		t.Fatal(err)
	}
	pkt = append(pkt, disco.Magic...)
	pkt = c.local.Public().AppendTo(pkt)
	box := c.local.Shared(c.server).Seal(msg.AppendMarshal(nil))
	pkt = append(pkt, box...)
	c.write(t, pkt)
}

func (c *testClient) readControlDiscoMsg(t *testing.T) disco.Message {
	b := c.read(t)
	gh := packet.GeneveHeader{}
	err := gh.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if gh.Protocol != packet.GeneveProtocolDisco {
		t.Fatal("unexpected geneve protocol")
	}
	if !gh.Control {
		t.Fatal("unexpected non-control")
	}
	if gh.VNI.Get() != c.vni {
		t.Fatal("unexpected vni")
	}
	b = b[packet.GeneveFixedHeaderLength:]
	headerLen := len(disco.Magic) + key.DiscoPublicRawLen
	if len(b) < headerLen {
		t.Fatal("disco message too short")
	}
	sender := key.DiscoPublicFromRaw32(mem.B(b[len(disco.Magic):headerLen]))
	if sender.Compare(c.server) != 0 {
		t.Fatal("unknown disco public key")
	}
	payload, ok := c.local.Shared(c.server).Open(b[headerLen:])
	if !ok {
		t.Fatal("failed to open sealed disco msg")
	}
	msg, err := disco.Parse(payload)
	if err != nil {
		t.Fatal("failed to parse disco payload")
	}
	return msg
}

func (c *testClient) handshake(t *testing.T) {
	generation := c.handshakeGeneration
	c.handshakeGeneration++
	common := disco.BindUDPRelayEndpointCommon{
		VNI:        c.vni,
		Generation: generation,
		RemoteKey:  c.remote,
	}
	c.writeControlDiscoMsg(t, &disco.BindUDPRelayEndpoint{
		BindUDPRelayEndpointCommon: common,
	})
	msg := c.readControlDiscoMsg(t)
	challenge, ok := msg.(*disco.BindUDPRelayEndpointChallenge)
	if !ok {
		t.Fatal("unexpected disco message type")
	}
	if challenge.Generation != common.Generation {
		t.Fatalf("rx'd challenge.Generation (%d) != %d", challenge.Generation, common.Generation)
	}
	if challenge.VNI != common.VNI {
		t.Fatalf("rx'd challenge.VNI (%d) != %d", challenge.VNI, common.VNI)
	}
	if challenge.RemoteKey != common.RemoteKey {
		t.Fatalf("rx'd challenge.RemoteKey (%v) != %v", challenge.RemoteKey, common.RemoteKey)
	}
	answer := &disco.BindUDPRelayEndpointAnswer{
		BindUDPRelayEndpointCommon: common,
	}
	answer.Challenge = challenge.Challenge
	c.writeControlDiscoMsg(t, answer)
}

func (c *testClient) close() {
	c.uc.Close()
}

func TestServer(t *testing.T) {
	discoA := key.NewDisco()
	discoB := key.NewDisco()

	cases := []struct {
		name                string
		staticAddrs         []netip.Addr
		forceClientsMixedAF bool
	}{
		{
			name:        "over ipv4",
			staticAddrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		},
		{
			name:        "over ipv6",
			staticAddrs: []netip.Addr{netip.MustParseAddr("::1")},
		},
		{
			name:                "mixed address families",
			staticAddrs:         []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")},
			forceClientsMixedAF: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewServer(t.Logf, 0, true)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			addrPorts := make([]netip.AddrPort, 0, len(tt.staticAddrs))
			for _, addr := range tt.staticAddrs {
				if addr.Is4() {
					addrPorts = append(addrPorts, netip.AddrPortFrom(addr, server.uc4Port))
				} else if server.uc6Port != 0 {
					addrPorts = append(addrPorts, netip.AddrPortFrom(addr, server.uc6Port))
				}
			}
			server.SetStaticAddrPorts(views.SliceOf(addrPorts))

			endpoint, err := server.AllocateEndpoint(discoA.Public(), discoB.Public())
			if err != nil {
				t.Fatal(err)
			}
			dupEndpoint, err := server.AllocateEndpoint(discoA.Public(), discoB.Public())
			if err != nil {
				t.Fatal(err)
			}

			// We expect the same endpoint details pre-handshake.
			if diff := cmp.Diff(dupEndpoint, endpoint, cmpopts.EquateComparable(netip.AddrPort{}, key.DiscoPublic{})); diff != "" {
				t.Fatalf("wrong dupEndpoint (-got +want)\n%s", diff)
			}

			if len(endpoint.AddrPorts) < 1 {
				t.Fatalf("unexpected endpoint.AddrPorts: %v", endpoint.AddrPorts)
			}
			tcAServerEndpointAddr := endpoint.AddrPorts[0]
			tcA := newTestClient(t, endpoint.VNI, tcAServerEndpointAddr, discoA, discoB.Public(), endpoint.ServerDisco)
			defer tcA.close()
			tcBServerEndpointAddr := tcAServerEndpointAddr
			if tt.forceClientsMixedAF {
				foundMixedAF := false
				for _, addr := range endpoint.AddrPorts {
					if addr.Addr().Is4() != tcBServerEndpointAddr.Addr().Is4() {
						tcBServerEndpointAddr = addr
						foundMixedAF = true
					}
				}
				if !foundMixedAF {
					t.Fatal("force clients to mixed address families is set, but relay server lacks address family diversity")
				}
			}
			tcB := newTestClient(t, endpoint.VNI, tcBServerEndpointAddr, discoB, discoA.Public(), endpoint.ServerDisco)
			defer tcB.close()

			for i := 0; i < 2; i++ {
				// We handshake both clients twice to guarantee server-side
				// packet reading goroutines, which are independent across
				// address families, have seen an answer from both clients
				// before proceeding. This is needed because the test assumes
				// that B's handshake is complete (the first send is A->B below),
				// but the server may not have handled B's handshake answer
				// before it handles A's data pkt towards B.
				//
				// Data transmissions following "re-handshakes" orient so that
				// the sender is the same as the party that performed the
				// handshake, for the same reasons.
				//
				// [magicsock.relayManager] is not prone to this issue as both
				// parties transmit data packets immediately following their
				// handshake answer.
				tcA.handshake(t)
				tcB.handshake(t)
			}

			dupEndpoint, err = server.AllocateEndpoint(discoA.Public(), discoB.Public())
			if err != nil {
				t.Fatal(err)
			}
			// We expect the same endpoint details post-handshake.
			if diff := cmp.Diff(dupEndpoint, endpoint, cmpopts.EquateComparable(netip.AddrPort{}, key.DiscoPublic{})); diff != "" {
				t.Fatalf("wrong dupEndpoint (-got +want)\n%s", diff)
			}

			txToB := []byte{1, 2, 3}
			tcA.writeDataPkt(t, txToB)
			rxFromA := tcB.readDataPkt(t)
			if !bytes.Equal(txToB, rxFromA) {
				t.Fatal("unexpected msg A->B")
			}

			txToA := []byte{4, 5, 6}
			tcB.writeDataPkt(t, txToA)
			rxFromB := tcA.readDataPkt(t)
			if !bytes.Equal(txToA, rxFromB) {
				t.Fatal("unexpected msg B->A")
			}

			tcAOnNewPort := newTestClient(t, endpoint.VNI, tcAServerEndpointAddr, discoA, discoB.Public(), endpoint.ServerDisco)
			tcAOnNewPort.handshakeGeneration = tcA.handshakeGeneration + 1
			defer tcAOnNewPort.close()

			// Handshake client A on a new source IP:port, verify we can send packets on the new binding
			tcAOnNewPort.handshake(t)

			fromAOnNewPort := []byte{7, 8, 9}
			tcAOnNewPort.writeDataPkt(t, fromAOnNewPort)
			rxFromA = tcB.readDataPkt(t)
			if !bytes.Equal(fromAOnNewPort, rxFromA) {
				t.Fatal("unexpected msg A->B")
			}

			tcBOnNewPort := newTestClient(t, endpoint.VNI, tcBServerEndpointAddr, discoB, discoA.Public(), endpoint.ServerDisco)
			tcBOnNewPort.handshakeGeneration = tcB.handshakeGeneration + 1
			defer tcBOnNewPort.close()

			// Handshake client B on a new source IP:port, verify we can send packets on the new binding
			tcBOnNewPort.handshake(t)

			fromBOnNewPort := []byte{7, 8, 9}
			tcBOnNewPort.writeDataPkt(t, fromBOnNewPort)
			rxFromB = tcAOnNewPort.readDataPkt(t)
			if !bytes.Equal(fromBOnNewPort, rxFromB) {
				t.Fatal("unexpected msg B->A")
			}
		})
	}
}

func TestServer_getNextVNILocked(t *testing.T) {
	t.Parallel()
	c := qt.New(t)
	s := &Server{
		nextVNI: minVNI,
		byVNI:   make(map[uint32]*serverEndpoint),
	}
	for i := uint64(0); i < uint64(totalPossibleVNI); i++ {
		vni, err := s.getNextVNILocked()
		if err != nil { // using quicktest here triples test time
			t.Fatal(err)
		}
		s.byVNI[vni] = nil
	}
	c.Assert(s.nextVNI, qt.Equals, minVNI)
	_, err := s.getNextVNILocked()
	c.Assert(err, qt.IsNotNil)
	delete(s.byVNI, minVNI)
	_, err = s.getNextVNILocked()
	c.Assert(err, qt.IsNil)
}

func Test_blakeMACFromBindMsg(t *testing.T) {
	var macSecret [blake2s.Size]byte
	rand.Read(macSecret[:])
	src := netip.MustParseAddrPort("[2001:db8::1]:7")

	msgA := disco.BindUDPRelayEndpointCommon{
		VNI:        1,
		Generation: 1,
		RemoteKey:  key.NewDisco().Public(),
		Challenge:  [32]byte{},
	}
	macA, err := blakeMACFromBindMsg(macSecret, src, msgA)
	if err != nil {
		t.Fatal(err)
	}

	msgB := msgA
	msgB.VNI++
	macB, err := blakeMACFromBindMsg(macSecret, src, msgB)
	if err != nil {
		t.Fatal(err)
	}
	if macA == macB {
		t.Fatalf("varying VNI input produced identical mac: %v", macA)
	}

	msgC := msgA
	msgC.Generation++
	macC, err := blakeMACFromBindMsg(macSecret, src, msgC)
	if err != nil {
		t.Fatal(err)
	}
	if macA == macC {
		t.Fatalf("varying Generation input produced identical mac: %v", macA)
	}

	msgD := msgA
	msgD.RemoteKey = key.NewDisco().Public()
	macD, err := blakeMACFromBindMsg(macSecret, src, msgD)
	if err != nil {
		t.Fatal(err)
	}
	if macA == macD {
		t.Fatalf("varying RemoteKey input produced identical mac: %v", macA)
	}

	msgE := msgA
	msgE.Challenge = [32]byte{0x01} // challenge is not part of the MAC and should be ignored
	macE, err := blakeMACFromBindMsg(macSecret, src, msgE)
	if err != nil {
		t.Fatal(err)
	}
	if macA != macE {
		t.Fatalf("varying Challenge input produced varying mac: %v", macA)
	}

	macSecretB := macSecret
	macSecretB[0] ^= 0xFF
	macF, err := blakeMACFromBindMsg(macSecretB, src, msgA)
	if err != nil {
		t.Fatal(err)
	}
	if macA == macF {
		t.Fatalf("varying macSecret input produced identical mac: %v", macA)
	}

	srcB := netip.AddrPortFrom(src.Addr(), src.Port()+1)
	macG, err := blakeMACFromBindMsg(macSecret, srcB, msgA)
	if err != nil {
		t.Fatal(err)
	}
	if macA == macG {
		t.Fatalf("varying src input produced identical mac: %v", macA)
	}
}

func Benchmark_blakeMACFromBindMsg(b *testing.B) {
	var macSecret [blake2s.Size]byte
	rand.Read(macSecret[:])
	src := netip.MustParseAddrPort("[2001:db8::1]:7")
	msg := disco.BindUDPRelayEndpointCommon{
		VNI:        1,
		Generation: 1,
		RemoteKey:  key.NewDisco().Public(),
		Challenge:  [32]byte{},
	}
	b.ReportAllocs()
	for b.Loop() {
		_, err := blakeMACFromBindMsg(macSecret, src, msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestServer_maybeRotateMACSecretLocked(t *testing.T) {
	s := &Server{}
	start := time.Now()
	s.maybeRotateMACSecretLocked(start)
	qt.Assert(t, len(s.macSecrets), qt.Equals, 1)
	macSecret := s.macSecrets[0]
	s.maybeRotateMACSecretLocked(start.Add(macSecretRotationInterval - time.Nanosecond))
	qt.Assert(t, len(s.macSecrets), qt.Equals, 1)
	qt.Assert(t, s.macSecrets[0], qt.Equals, macSecret)
	s.maybeRotateMACSecretLocked(start.Add(macSecretRotationInterval))
	qt.Assert(t, len(s.macSecrets), qt.Equals, 2)
	qt.Assert(t, s.macSecrets[1], qt.Equals, macSecret)
	qt.Assert(t, s.macSecrets[0], qt.Not(qt.Equals), s.macSecrets[1])
	s.maybeRotateMACSecretLocked(s.macSecretRotatedAt.Add(macSecretRotationInterval))
	qt.Assert(t, macSecret, qt.Not(qt.Equals), s.macSecrets[0])
	qt.Assert(t, macSecret, qt.Not(qt.Equals), s.macSecrets[1])
	qt.Assert(t, s.macSecrets[0], qt.Not(qt.Equals), s.macSecrets[1])
}
