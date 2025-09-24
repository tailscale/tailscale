// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derpserver

import (
	"bufio"
	"cmp"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"expvar"
	"fmt"
	"log"
	"net"
	"os"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"go4.org/mem"
	"golang.org/x/time/rate"
	"tailscale.com/derp"
	"tailscale.com/derp/derpconst"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const testMeshKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestSetMeshKey(t *testing.T) {
	for name, tt := range map[string]struct {
		key     string
		want    key.DERPMesh
		wantErr bool
	}{
		"clobber": {
			key:     testMeshKey,
			wantErr: false,
		},
		"invalid": {
			key:     "badf00d",
			wantErr: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := &Server{}

			err := s.SetMeshKey(tt.key)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected err")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}

			want, err := key.ParseDERPMesh(tt.key)
			if err != nil {
				t.Fatal(err)
			}
			if !s.meshKey.Equal(want) {
				t.Fatalf("got %v, want %v", s.meshKey, want)
			}
		})
	}
}

func TestIsMeshPeer(t *testing.T) {
	s := &Server{}
	err := s.SetMeshKey(testMeshKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, tt := range map[string]struct {
		want       bool
		meshKey    string
		wantAllocs float64
	}{
		"nil": {
			want:       false,
			wantAllocs: 0,
		},
		"mismatch": {
			meshKey:    "6d529e9d4ef632d22d4a4214cb49da8f1ba1b72697061fb24e312984c35ec8d8",
			want:       false,
			wantAllocs: 1,
		},
		"match": {
			meshKey:    testMeshKey,
			want:       true,
			wantAllocs: 0,
		},
	} {
		t.Run(name, func(t *testing.T) {
			var got bool
			var mKey key.DERPMesh
			if tt.meshKey != "" {
				mKey, err = key.ParseDERPMesh(tt.meshKey)
				if err != nil {
					t.Fatalf("ParseDERPMesh(%q) failed: %v", tt.meshKey, err)
				}
			}

			info := derp.ClientInfo{
				MeshKey: mKey,
			}
			allocs := testing.AllocsPerRun(1, func() {
				got = s.isMeshPeer(&info)
			})
			if got != tt.want {
				t.Fatalf("got %t, want %t: info = %#v", got, tt.want, info)
			}

			if allocs != tt.wantAllocs && tt.want {
				t.Errorf("%f allocations, want %f", allocs, tt.wantAllocs)
			}
		})
	}
}

type testFwd int

func (testFwd) ForwardPacket(key.NodePublic, key.NodePublic, []byte) error {
	panic("not called in tests")
}
func (testFwd) String() string {
	panic("not called in tests")
}

func pubAll(b byte) (ret key.NodePublic) {
	var bs [32]byte
	for i := range bs {
		bs[i] = b
	}
	return key.NodePublicFromRaw32(mem.B(bs[:]))
}

func TestForwarderRegistration(t *testing.T) {
	s := &Server{
		clients:     make(map[key.NodePublic]*clientSet),
		clientsMesh: map[key.NodePublic]PacketForwarder{},
	}
	want := func(want map[key.NodePublic]PacketForwarder) {
		t.Helper()
		if got := s.clientsMesh; !reflect.DeepEqual(got, want) {
			t.Fatalf("mismatch\n got: %v\nwant: %v\n", got, want)
		}
	}
	wantCounter := func(c *expvar.Int, want int) {
		t.Helper()
		if got := c.Value(); got != int64(want) {
			t.Errorf("counter = %v; want %v", got, want)
		}
	}
	singleClient := func(c *sclient) *clientSet {
		cs := &clientSet{}
		cs.activeClient.Store(c)
		return cs
	}

	u1 := pubAll(1)
	u2 := pubAll(2)
	u3 := pubAll(3)

	s.AddPacketForwarder(u1, testFwd(1))
	s.AddPacketForwarder(u2, testFwd(2))
	want(map[key.NodePublic]PacketForwarder{
		u1: testFwd(1),
		u2: testFwd(2),
	})

	// Verify a remove of non-registered forwarder is no-op.
	s.RemovePacketForwarder(u2, testFwd(999))
	want(map[key.NodePublic]PacketForwarder{
		u1: testFwd(1),
		u2: testFwd(2),
	})

	// Verify a remove of non-registered user is no-op.
	s.RemovePacketForwarder(u3, testFwd(1))
	want(map[key.NodePublic]PacketForwarder{
		u1: testFwd(1),
		u2: testFwd(2),
	})

	// Actual removal.
	s.RemovePacketForwarder(u2, testFwd(2))
	want(map[key.NodePublic]PacketForwarder{
		u1: testFwd(1),
	})

	// Adding a dup for a user.
	wantCounter(&s.multiForwarderCreated, 0)
	s.AddPacketForwarder(u1, testFwd(100))
	s.AddPacketForwarder(u1, testFwd(100)) // dup to trigger dup path
	want(map[key.NodePublic]PacketForwarder{
		u1: newMultiForwarder(testFwd(1), testFwd(100)),
	})
	wantCounter(&s.multiForwarderCreated, 1)

	// Removing a forwarder in a multi set that doesn't exist; does nothing.
	s.RemovePacketForwarder(u1, testFwd(55))
	want(map[key.NodePublic]PacketForwarder{
		u1: newMultiForwarder(testFwd(1), testFwd(100)),
	})

	// Removing a forwarder in a multi set that does exist should collapse it away
	// from being a multiForwarder.
	wantCounter(&s.multiForwarderDeleted, 0)
	s.RemovePacketForwarder(u1, testFwd(1))
	want(map[key.NodePublic]PacketForwarder{
		u1: testFwd(100),
	})
	wantCounter(&s.multiForwarderDeleted, 1)

	// Removing an entry for a client that's still connected locally should result
	// in a nil forwarder.
	u1c := &sclient{
		key:  u1,
		logf: logger.Discard,
	}
	s.clients[u1] = singleClient(u1c)
	s.RemovePacketForwarder(u1, testFwd(100))
	want(map[key.NodePublic]PacketForwarder{
		u1: nil,
	})

	// But once that client disconnects, it should go away.
	s.unregisterClient(u1c)
	want(map[key.NodePublic]PacketForwarder{})

	// But if it already has a forwarder, it's not removed.
	s.AddPacketForwarder(u1, testFwd(2))
	s.unregisterClient(u1c)
	want(map[key.NodePublic]PacketForwarder{
		u1: testFwd(2),
	})

	// Now pretend u1 was already connected locally (so clientsMesh[u1] is nil), and then we heard
	// that they're also connected to a peer of ours. That shouldn't transition the forwarder
	// from nil to the new one, not a multiForwarder.
	s.clients[u1] = singleClient(u1c)
	s.clientsMesh[u1] = nil
	want(map[key.NodePublic]PacketForwarder{
		u1: nil,
	})
	s.AddPacketForwarder(u1, testFwd(3))
	want(map[key.NodePublic]PacketForwarder{
		u1: testFwd(3),
	})
}

type channelFwd struct {
	// id is to ensure that different instances that reference the
	// same channel are not equal, as they are used as keys in the
	// multiForwarder map.
	id int
	c  chan []byte
}

func (f channelFwd) String() string { return "" }
func (f channelFwd) ForwardPacket(_ key.NodePublic, _ key.NodePublic, packet []byte) error {
	f.c <- packet
	return nil
}

func TestMultiForwarder(t *testing.T) {
	received := 0
	var wg sync.WaitGroup
	ch := make(chan []byte)
	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		clients:     make(map[key.NodePublic]*clientSet),
		clientsMesh: map[key.NodePublic]PacketForwarder{},
	}
	u := pubAll(1)
	s.AddPacketForwarder(u, channelFwd{1, ch})

	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ch:
				received += 1
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			s.AddPacketForwarder(u, channelFwd{2, ch})
			s.AddPacketForwarder(u, channelFwd{3, ch})
			s.RemovePacketForwarder(u, channelFwd{2, ch})
			s.RemovePacketForwarder(u, channelFwd{1, ch})
			s.AddPacketForwarder(u, channelFwd{1, ch})
			s.RemovePacketForwarder(u, channelFwd{3, ch})
			if ctx.Err() != nil {
				return
			}
		}
	}()

	// Number of messages is chosen arbitrarily, just for this loop to
	// run long enough concurrently with {Add,Remove}PacketForwarder loop above.
	numMsgs := 5000
	var fwd PacketForwarder
	for i := range numMsgs {
		s.mu.Lock()
		fwd = s.clientsMesh[u]
		s.mu.Unlock()
		fwd.ForwardPacket(u, u, []byte(strconv.Itoa(i)))
	}

	cancel()
	wg.Wait()
	if received != numMsgs {
		t.Errorf("expected %d messages to be forwarded; got %d", numMsgs, received)
	}
}
func TestMetaCert(t *testing.T) {
	priv := key.NewNode()
	pub := priv.Public()
	s := New(priv, t.Logf)

	certBytes := s.MetaCert()
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		log.Fatal(err)
	}
	if fmt.Sprint(cert.SerialNumber) != fmt.Sprint(derp.ProtocolVersion) {
		t.Errorf("serial = %v; want %v", cert.SerialNumber, derp.ProtocolVersion)
	}
	if g, w := cert.Subject.CommonName, derpconst.MetaCertCommonNamePrefix+pub.UntypedHexString(); g != w {
		t.Errorf("CommonName = %q; want %q", g, w)
	}
	if n := len(cert.Extensions); n != 1 {
		t.Fatalf("got %d extensions; want 1", n)
	}

	// oidExtensionBasicConstraints is the Basic Constraints ID copied
	// from the x509 package.
	oidExtensionBasicConstraints := asn1.ObjectIdentifier{2, 5, 29, 19}

	if id := cert.Extensions[0].Id; !id.Equal(oidExtensionBasicConstraints) {
		t.Errorf("extension ID = %v; want %v", id, oidExtensionBasicConstraints)
	}
}

func TestServerDupClients(t *testing.T) {
	serverPriv := key.NewNode()
	var s *Server

	clientPriv := key.NewNode()
	clientPub := clientPriv.Public()

	var c1, c2, c3 *sclient
	var clientName map[*sclient]string

	// run starts a new test case and resets clients back to their zero values.
	run := func(name string, dupPolicy dupPolicy, f func(t *testing.T)) {
		s = New(serverPriv, t.Logf)
		s.dupPolicy = dupPolicy
		c1 = &sclient{key: clientPub, logf: logger.WithPrefix(t.Logf, "c1: ")}
		c2 = &sclient{key: clientPub, logf: logger.WithPrefix(t.Logf, "c2: ")}
		c3 = &sclient{key: clientPub, logf: logger.WithPrefix(t.Logf, "c3: ")}
		clientName = map[*sclient]string{
			c1: "c1",
			c2: "c2",
			c3: "c3",
		}
		t.Run(name, f)
	}
	runBothWays := func(name string, f func(t *testing.T)) {
		run(name+"_disablefighters", disableFighters, f)
		run(name+"_lastwriteractive", lastWriterIsActive, f)
	}
	wantSingleClient := func(t *testing.T, want *sclient) {
		t.Helper()
		got, ok := s.clients[want.key]
		if !ok {
			t.Error("no clients for key")
			return
		}
		if got.dup != nil {
			t.Errorf("unexpected dup set for single client")
		}
		cur := got.activeClient.Load()
		if cur != want {
			t.Errorf("active client = %q; want %q", clientName[cur], clientName[want])
		}
		if cur != nil {
			if cur.isDup.Load() {
				t.Errorf("unexpected isDup on singleClient")
			}
			if cur.isDisabled.Load() {
				t.Errorf("unexpected isDisabled on singleClient")
			}
		}
	}
	wantNoClient := func(t *testing.T) {
		t.Helper()
		_, ok := s.clients[clientPub]
		if !ok {
			// Good
			return
		}
		t.Errorf("got client; want empty")
	}
	wantDupSet := func(t *testing.T) *dupClientSet {
		t.Helper()
		cs, ok := s.clients[clientPub]
		if !ok {
			t.Fatal("no set for key; want dup set")
			return nil
		}
		if cs.dup != nil {
			return cs.dup
		}
		t.Fatalf("no dup set for key; want dup set")
		return nil
	}
	wantActive := func(t *testing.T, want *sclient) {
		t.Helper()
		set, ok := s.clients[clientPub]
		if !ok {
			t.Error("no set for key")
			return
		}
		got := set.activeClient.Load()
		if got != want {
			t.Errorf("active client = %q; want %q", clientName[got], clientName[want])
		}
	}
	checkDup := func(t *testing.T, c *sclient, want bool) {
		t.Helper()
		if got := c.isDup.Load(); got != want {
			t.Errorf("client %q isDup = %v; want %v", clientName[c], got, want)
		}
	}
	checkDisabled := func(t *testing.T, c *sclient, want bool) {
		t.Helper()
		if got := c.isDisabled.Load(); got != want {
			t.Errorf("client %q isDisabled = %v; want %v", clientName[c], got, want)
		}
	}
	wantDupConns := func(t *testing.T, want int) {
		t.Helper()
		if got := s.dupClientConns.Value(); got != int64(want) {
			t.Errorf("dupClientConns = %v; want %v", got, want)
		}
	}
	wantDupKeys := func(t *testing.T, want int) {
		t.Helper()
		if got := s.dupClientKeys.Value(); got != int64(want) {
			t.Errorf("dupClientKeys = %v; want %v", got, want)
		}
	}

	// Common case: a single client comes and goes, with no dups.
	runBothWays("one_comes_and_goes", func(t *testing.T) {
		wantNoClient(t)
		s.registerClient(c1)
		wantSingleClient(t, c1)
		s.unregisterClient(c1)
		wantNoClient(t)
	})

	// A still somewhat common case: a single client was
	// connected and then their wifi dies or laptop closes
	// or they switch networks and connect from a
	// different network. They have two connections but
	// it's not very bad. Only their new one is
	// active. The last one, being dead, doesn't send and
	// thus the new one doesn't get disabled.
	runBothWays("small_overlap_replacement", func(t *testing.T) {
		wantNoClient(t)
		s.registerClient(c1)
		wantSingleClient(t, c1)
		wantActive(t, c1)
		wantDupKeys(t, 0)
		wantDupKeys(t, 0)

		s.registerClient(c2) // wifi dies; c2 replacement connects
		wantDupSet(t)
		wantDupConns(t, 2)
		wantDupKeys(t, 1)
		checkDup(t, c1, true)
		checkDup(t, c2, true)
		checkDisabled(t, c1, false)
		checkDisabled(t, c2, false)
		wantActive(t, c2) // sends go to the replacement

		s.unregisterClient(c1) // c1 finally times out
		wantSingleClient(t, c2)
		checkDup(t, c2, false) // c2 is longer a dup
		wantActive(t, c2)
		wantDupConns(t, 0)
		wantDupKeys(t, 0)
	})

	// Key cloning situation with concurrent clients, both trying
	// to write.
	run("concurrent_dups_get_disabled", disableFighters, func(t *testing.T) {
		wantNoClient(t)
		s.registerClient(c1)
		wantSingleClient(t, c1)
		wantActive(t, c1)
		s.registerClient(c2)
		wantDupSet(t)
		wantDupKeys(t, 1)
		wantDupConns(t, 2)
		wantActive(t, c2)
		checkDup(t, c1, true)
		checkDup(t, c2, true)
		checkDisabled(t, c1, false)
		checkDisabled(t, c2, false)

		s.noteClientActivity(c2)
		checkDisabled(t, c1, false)
		checkDisabled(t, c2, false)
		s.noteClientActivity(c1)
		checkDisabled(t, c1, true)
		checkDisabled(t, c2, true)
		wantActive(t, nil)

		s.registerClient(c3)
		wantActive(t, c3)
		checkDisabled(t, c3, false)
		wantDupKeys(t, 1)
		wantDupConns(t, 3)

		s.unregisterClient(c3)
		wantActive(t, nil)
		wantDupKeys(t, 1)
		wantDupConns(t, 2)

		s.unregisterClient(c2)
		wantSingleClient(t, c1)
		wantDupKeys(t, 0)
		wantDupConns(t, 0)
	})

	// Key cloning with an A->B->C->A series instead.
	run("concurrent_dups_three_parties", disableFighters, func(t *testing.T) {
		wantNoClient(t)
		s.registerClient(c1)
		s.registerClient(c2)
		s.registerClient(c3)
		s.noteClientActivity(c1)
		checkDisabled(t, c1, true)
		checkDisabled(t, c2, true)
		checkDisabled(t, c3, true)
		wantActive(t, nil)
	})

	run("activity_promotes_primary_when_nil", disableFighters, func(t *testing.T) {
		wantNoClient(t)

		// Last registered client is the active one...
		s.registerClient(c1)
		wantActive(t, c1)
		s.registerClient(c2)
		wantActive(t, c2)
		s.registerClient(c3)
		s.noteClientActivity(c2)
		wantActive(t, c3)

		// But if the last one goes away, the one with the
		// most recent activity wins.
		s.unregisterClient(c3)
		wantActive(t, c2)
	})

	run("concurrent_dups_three_parties_last_writer", lastWriterIsActive, func(t *testing.T) {
		wantNoClient(t)

		s.registerClient(c1)
		wantActive(t, c1)
		s.registerClient(c2)
		wantActive(t, c2)

		s.noteClientActivity(c1)
		checkDisabled(t, c1, false)
		checkDisabled(t, c2, false)
		wantActive(t, c1)

		s.noteClientActivity(c2)
		checkDisabled(t, c1, false)
		checkDisabled(t, c2, false)
		wantActive(t, c2)

		s.unregisterClient(c2)
		checkDisabled(t, c1, false)
		wantActive(t, c1)
	})
}

func TestLimiter(t *testing.T) {
	rl := rate.NewLimiter(rate.Every(time.Minute), 100)
	for i := range 200 {
		r := rl.Reserve()
		d := r.Delay()
		t.Logf("i=%d, allow=%v, d=%v", i, r.OK(), d)
	}
}

// BenchmarkConcurrentStreams exercises mutex contention on a
// single Server instance with multiple concurrent client flows.
func BenchmarkConcurrentStreams(b *testing.B) {
	serverPrivateKey := key.NewNode()
	s := New(serverPrivateKey, logger.Discard)
	defer s.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for ctx.Err() == nil {
			connIn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				b.Error(err)
				return
			}

			brwServer := bufio.NewReadWriter(bufio.NewReader(connIn), bufio.NewWriter(connIn))
			go s.Accept(ctx, connIn, brwServer, "test-client")
		}
	}()

	newClient := func(t testing.TB) *derp.Client {
		t.Helper()
		connOut, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		t.Cleanup(func() { connOut.Close() })

		k := key.NewNode()

		brw := bufio.NewReadWriter(bufio.NewReader(connOut), bufio.NewWriter(connOut))
		client, err := derp.NewClient(k, connOut, brw, logger.Discard)
		if err != nil {
			b.Fatalf("client: %v", err)
		}
		return client
	}

	b.RunParallel(func(pb *testing.PB) {
		c1, c2 := newClient(b), newClient(b)
		const packetSize = 100
		msg := make([]byte, packetSize)
		for pb.Next() {
			if err := c1.Send(c2.PublicKey(), msg); err != nil {
				b.Fatal(err)
			}
			_, err := c2.Recv()
			if err != nil {
				return
			}
		}
	})
}

func BenchmarkSendRecv(b *testing.B) {
	for _, size := range []int{10, 100, 1000, 10000} {
		b.Run(fmt.Sprintf("msgsize=%d", size), func(b *testing.B) { benchmarkSendRecvSize(b, size) })
	}
}

func benchmarkSendRecvSize(b *testing.B, packetSize int) {
	serverPrivateKey := key.NewNode()
	s := New(serverPrivateKey, logger.Discard)
	defer s.Close()

	k := key.NewNode()
	clientKey := k.Public()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	connOut, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	defer connOut.Close()

	connIn, err := ln.Accept()
	if err != nil {
		b.Fatal(err)
	}
	defer connIn.Close()

	brwServer := bufio.NewReadWriter(bufio.NewReader(connIn), bufio.NewWriter(connIn))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Accept(ctx, connIn, brwServer, "test-client")

	brw := bufio.NewReadWriter(bufio.NewReader(connOut), bufio.NewWriter(connOut))
	client, err := derp.NewClient(k, connOut, brw, logger.Discard)
	if err != nil {
		b.Fatalf("client: %v", err)
	}

	go func() {
		for {
			_, err := client.Recv()
			if err != nil {
				return
			}
		}
	}()

	msg := make([]byte, packetSize)
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := client.Send(clientKey, msg); err != nil {
			b.Fatal(err)
		}
	}
}

func TestParseSSOutput(t *testing.T) {
	contents, err := os.ReadFile("testdata/example_ss.txt")
	if err != nil {
		t.Errorf("os.ReadFile(example_ss.txt) failed: %v", err)
	}
	seen := parseSSOutput(string(contents))
	if len(seen) == 0 {
		t.Errorf("parseSSOutput expected non-empty map")
	}
}

func TestGetPerClientSendQueueDepth(t *testing.T) {
	c := qt.New(t)
	envKey := "TS_DEBUG_DERP_PER_CLIENT_SEND_QUEUE_DEPTH"

	testCases := []struct {
		envVal string
		want   int
	}{
		// Empty case, envknob treats empty as missing also.
		{
			"", defaultPerClientSendQueueDepth,
		},
		{
			"64", 64,
		},
	}

	for _, tc := range testCases {
		t.Run(cmp.Or(tc.envVal, "empty"), func(t *testing.T) {
			t.Setenv(envKey, tc.envVal)
			val := getPerClientSendQueueDepth()
			c.Assert(val, qt.Equals, tc.want)
		})
	}
}
