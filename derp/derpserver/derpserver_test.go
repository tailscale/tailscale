// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derpserver

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"expvar"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/axiomhq/hyperloglog"
	qt "github.com/frankban/quicktest"
	"go4.org/mem"
	"golang.org/x/time/rate"
	"tailscale.com/derp"
	"tailscale.com/derp/derpconst"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/set"
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

func TestVerifyClientDisallowedAppNames(t *testing.T) {
	ctx := t.Context()
	s := &Server{}
	if err := s.SetMeshKey(testMeshKey); err != nil {
		t.Fatal(err)
	}
	s.SetDisallowedAppNames([]string{"badapp", "worseapp"})

	k := key.NewNode().Public()
	ip := netip.MustParseAddr("2.3.4.5")

	if err := s.verifyClient(ctx, k, &derp.ClientInfo{AppName: "badapp"}, ip); err == nil {
		t.Error("disallowed app name: got nil error; want error")
	}
	if err := s.verifyClient(ctx, k, &derp.ClientInfo{AppName: "goodapp"}, ip); err != nil {
		t.Errorf("allowed app name: unexpected error: %v", err)
	}
	if err := s.verifyClient(ctx, k, &derp.ClientInfo{}, ip); err != nil {
		t.Errorf("empty app name: unexpected error: %v", err)
	}

	// Trusted mesh peers are exempt.
	mk, err := key.ParseDERPMesh(testMeshKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.verifyClient(ctx, k, &derp.ClientInfo{AppName: "badapp", MeshKey: mk}, ip); err != nil {
		t.Errorf("mesh peer with disallowed app name: unexpected error: %v", err)
	}
}

func TestRecvClientKeyAppName(t *testing.T) {
	serverPriv := key.NewNode()
	s := New(serverPriv, t.Logf)
	defer s.Close()

	tests := []struct {
		appName string
		wantErr bool
	}{
		{"some-client", false},
		{"", false},
		{strings.Repeat("x", derp.MaxAppNameLen+1), true},
		{"new\nline", true},
	}
	for _, tt := range tests {
		clientPriv := key.NewNode()
		msg, err := json.Marshal(derp.ClientInfo{AppName: tt.appName})
		if err != nil {
			t.Fatal(err)
		}
		payload := clientPriv.Public().AppendTo(nil)
		payload = append(payload, clientPriv.SealTo(serverPriv.Public(), msg)...)

		var buf bytes.Buffer
		bw := bufio.NewWriter(&buf)
		if err := derp.WriteFrame(bw, derp.FrameClientInfo, payload); err != nil {
			t.Fatal(err)
		}
		_, _, err = s.recvClientKey(bufio.NewReader(&buf))
		if gotErr := err != nil; gotErr != tt.wantErr {
			t.Errorf("recvClientKey with AppName %.40q: err = %v; wantErr = %v", tt.appName, err, tt.wantErr)
		}
	}
}

type testFwd int

func (testFwd) ForwardPacket(key.NodePublic, key.NodePublic, derp.LoanedBytes) error {
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
	s.clients.Store(u1, singleClient(u1c))
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
	s.clients.Store(u1, singleClient(u1c))
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
func (f channelFwd) ForwardPacket(_ key.NodePublic, _ key.NodePublic, packet derp.LoanedBytes) error {
	f.c <- packet.Clone()
	return nil
}

func TestMultiForwarder(t *testing.T) {
	received := 0
	var wg sync.WaitGroup
	ch := make(chan []byte)
	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
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
		fwd.ForwardPacket(u, u, derp.LoanBytes([]byte(strconv.Itoa(i))))
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

// TestModifyTLSConfigToAddMetaCert verifies that the wrapped GetCertificate
// appends the meta cert to a copy of the provider's chain without mutating
// the shared *tls.Certificate returned by the underlying provider (issue
// 20352). Cert providers such as autocert cache and return the same
// *tls.Certificate for concurrent handshakes, so appending to its
// Certificate slice in place is both a data race and unbounded growth of
// the served chain.
func TestModifyTLSConfigToAddMetaCert(t *testing.T) {
	s := New(key.NewNode(), t.Logf)

	// Give the shared chain slice spare capacity so that a regression to a
	// plain append (rather than a copy into a freshly allocated slice)
	// writes into the shared backing array. Concurrent goroutines doing so
	// is a write-write race caught by the race detector, and the write
	// itself is caught by the backing-array check after wg.Wait below.
	chain := make([][]byte, 1, 2)
	chain[0] = []byte{1, 2, 3}
	shared := &tls.Certificate{
		Certificate: chain,
	}
	c := &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return shared, nil
		},
	}
	s.ModifyTLSConfigToAddMetaCert(c)

	var wg sync.WaitGroup
	// The goroutine count and iteration count are arbitrary: correctness is
	// checked deterministically by the assertions below; the concurrency
	// exists only to give the race detector overlapping calls to observe.
	for range 10 {
		wg.Go(func() {
			for range 10 {
				cert, err := c.GetCertificate(&tls.ClientHelloInfo{})
				if err != nil {
					t.Errorf("GetCertificate: %v", err)
					return
				}
				if len(cert.Certificate) != 2 {
					t.Errorf("chain length = %d; want 2", len(cert.Certificate))
					return
				}
				if !bytes.Equal(cert.Certificate[0], []byte{1, 2, 3}) {
					t.Errorf("chain[0] = %v; want provider's leaf cert %v", cert.Certificate[0], []byte{1, 2, 3})
					return
				}
				if !bytes.Equal(cert.Certificate[1], s.MetaCert()) {
					t.Errorf("chain[1] = %v; want meta cert", cert.Certificate[1])
					return
				}
			}
		})
	}
	wg.Wait()

	if len(shared.Certificate) != 1 {
		t.Errorf("shared cert chain length = %d; want 1 (must not be mutated)", len(shared.Certificate))
	}
	if got := chain[:cap(chain)][1]; got != nil {
		t.Errorf("shared cert backing array was written: %v", got)
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
		got, ok := s.clients.Load(want.key)
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
		_, ok := s.clients.Load(clientPub)
		if !ok {
			// Good
			return
		}
		t.Errorf("got client; want empty")
	}
	wantDupSet := func(t *testing.T) *dupClientSet {
		t.Helper()
		cs, ok := s.clients.Load(clientPub)
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
		set, ok := s.clients.Load(clientPub)
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

	ctx := b.Context()

	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			connIn, err := ln.Accept()
			if err != nil {
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

	ln.Close()
	<-acceptDone
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

func TestServeDebugTrafficUniqueSenders(t *testing.T) {
	s := New(key.NewNode(), t.Logf)
	defer s.Close()

	clientKey := key.NewNode().Public()
	c := &sclient{
		key:               clientKey,
		s:                 s,
		logf:              logger.Discard,
		senderCardinality: hyperloglog.New(),
	}

	for range 5 {
		c.senderCardinality.Insert(key.NewNode().Public().AppendTo(nil))
	}

	s.mu.Lock()
	cs := &clientSet{}
	cs.activeClient.Store(c)
	s.clients.Store(clientKey, cs)
	s.mu.Unlock()

	estimate := c.EstimatedUniqueSenders()
	t.Logf("Estimated unique senders: %d", estimate)
	if estimate < 4 || estimate > 6 {
		t.Errorf("EstimatedUniqueSenders() = %d, want ~5 (4-6 range)", estimate)
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
		// Zero and negative values are treated as unset.
		{
			"0", defaultPerClientSendQueueDepth,
		},
		{
			"-5", defaultPerClientSendQueueDepth,
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

func TestSenderCardinality(t *testing.T) {
	s := New(key.NewNode(), t.Logf)
	defer s.Close()

	c := &sclient{
		key:  key.NewNode().Public(),
		s:    s,
		logf: logger.WithPrefix(t.Logf, "test client: "),
	}

	if got := c.EstimatedUniqueSenders(); got != 0 {
		t.Errorf("EstimatedUniqueSenders() before init = %d, want 0", got)
	}

	c.senderCardinality = hyperloglog.New()

	if got := c.EstimatedUniqueSenders(); got != 0 {
		t.Errorf("EstimatedUniqueSenders() with no senders = %d, want 0", got)
	}

	senders := make([]key.NodePublic, 10)
	for i := range senders {
		senders[i] = key.NewNode().Public()
		c.senderCardinality.Insert(senders[i].AppendTo(nil))
	}

	estimate := c.EstimatedUniqueSenders()
	t.Logf("Estimated unique senders after 10 inserts: %d", estimate)

	if estimate < 8 || estimate > 12 {
		t.Errorf("EstimatedUniqueSenders() = %d, want ~10 (8-12 range)", estimate)
	}

	for i := range 5 {
		c.senderCardinality.Insert(senders[i].AppendTo(nil))
	}

	estimate2 := c.EstimatedUniqueSenders()
	t.Logf("Estimated unique senders after duplicates: %d", estimate2)

	if estimate2 < 8 || estimate2 > 12 {
		t.Errorf("EstimatedUniqueSenders() after duplicates = %d, want ~10 (8-12 range)", estimate2)
	}
}

func TestSenderCardinality100(t *testing.T) {
	s := New(key.NewNode(), t.Logf)
	defer s.Close()

	c := &sclient{
		key:               key.NewNode().Public(),
		s:                 s,
		logf:              logger.WithPrefix(t.Logf, "test client: "),
		senderCardinality: hyperloglog.New(),
	}

	numSenders := 100
	for range numSenders {
		c.senderCardinality.Insert(key.NewNode().Public().AppendTo(nil))
	}

	estimate := c.EstimatedUniqueSenders()
	t.Logf("Estimated unique senders for 100 actual senders: %d", estimate)

	if estimate < 85 || estimate > 115 {
		t.Errorf("EstimatedUniqueSenders() = %d, want ~100 (85-115 range)", estimate)
	}
}

func TestSenderCardinalityTracking(t *testing.T) {
	s := New(key.NewNode(), t.Logf)
	defer s.Close()

	c := &sclient{
		key:               key.NewNode().Public(),
		s:                 s,
		logf:              logger.WithPrefix(t.Logf, "test client: "),
		senderCardinality: hyperloglog.New(),
	}

	zeroKey := key.NodePublic{}
	if zeroKey != (key.NodePublic{}) {
		c.senderCardinality.Insert(zeroKey.AppendTo(nil))
	}

	if estimate := c.EstimatedUniqueSenders(); estimate != 0 {
		t.Errorf("EstimatedUniqueSenders() after zero key = %d, want 0", estimate)
	}

	sender1 := key.NewNode().Public()
	sender2 := key.NewNode().Public()

	if sender1 != (key.NodePublic{}) {
		c.senderCardinality.Insert(sender1.AppendTo(nil))
	}
	if sender2 != (key.NodePublic{}) {
		c.senderCardinality.Insert(sender2.AppendTo(nil))
	}

	estimate := c.EstimatedUniqueSenders()
	t.Logf("Estimated unique senders after 2 senders: %d", estimate)

	if estimate < 1 || estimate > 3 {
		t.Errorf("EstimatedUniqueSenders() = %d, want ~2 (1-3 range)", estimate)
	}
}

func BenchmarkHyperLogLogInsert(b *testing.B) {
	hll := hyperloglog.New()
	sender := key.NewNode().Public()
	senderBytes := sender.AppendTo(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hll.Insert(senderBytes)
	}
}

func BenchmarkHyperLogLogInsertUnique(b *testing.B) {
	hll := hyperloglog.New()

	b.ResetTimer()

	buf := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint64(buf, uint64(i))
		hll.Insert(buf)
	}
}

func BenchmarkHyperLogLogEstimate(b *testing.B) {
	hll := hyperloglog.New()

	for range 100 {
		hll.Insert(key.NewNode().Public().AppendTo(nil))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hll.Estimate()
	}
}

func TestPerClientRateLimit(t *testing.T) {
	t.Run("throttled", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			s := New(key.NewNode(), logger.Discard)
			defer s.Close()

			c := &sclient{
				ctx: ctx,
				s:   s,
			}
			lim := rate.NewLimiter(rate.Limit(minRateLimitTokenBucketSize), minRateLimitTokenBucketSize)
			c.recvLim.Store(lim)
			wantTokens := func(t *testing.T, wantTokens float64) {
				t.Helper()
				if lim.Tokens() != wantTokens {
					t.Fatalf("want tokens: %v got: %v", wantTokens, lim.Tokens())
				}
			}

			// First call within burst should not block.
			c.rateLimit(minRateLimitTokenBucketSize)

			wantTokens(t, 0)

			// Next call exceeds burst, should block until tokens replenish.
			done := make(chan error, 1)
			go func() {
				done <- c.rateLimit(minRateLimitTokenBucketSize)
			}()

			// After settling, the goroutine should be blocked (no result yet).
			synctest.Wait()
			select {
			case err := <-done:
				t.Fatalf("rateLimit should have blocked, but returned: %v", err)
			default:
			}

			// Advance time by 1 second, the goroutine should be unblocked
			time.Sleep(1 * time.Second)
			synctest.Wait()

			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("rateLimit after time advance: %v", err)
				}
			default:
				t.Fatal("rateLimit should have unblocked after 1s")
			}

			wantTokens(t, 0)

			// The second rateLimit call had to wait
			if got := s.rateLimitPerClientWaited.Value(); got != 1 {
				t.Fatalf("rateLimitPerClientWaited = %d, want 1", got)
			}
		})
	})

	t.Run("context_canceled", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())

			s := New(key.NewNode(), logger.Discard)
			defer s.Close()

			c := &sclient{
				ctx: ctx,
				s:   s,
			}
			lim := rate.NewLimiter(rate.Limit(minRateLimitTokenBucketSize), minRateLimitTokenBucketSize)
			c.recvLim.Store(lim)

			// Exhaust burst.
			if err := c.rateLimit(minRateLimitTokenBucketSize); err != nil {
				t.Fatalf("rateLimit: %v", err)
			}

			done := make(chan error, 1)
			go func() {
				done <- c.rateLimit(minRateLimitTokenBucketSize)
			}()
			synctest.Wait()

			// Cancel the context; the blocked rateLimit should return an error.
			cancel()
			synctest.Wait()

			select {
			case err := <-done:
				if err == nil {
					t.Fatal("expected error from canceled context")
				}
			default:
				t.Fatal("rateLimit should have returned after context cancelation")
			}
		})
	})

	t.Run("mesh_peer_exempt", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		// Mesh peers have nil recvLim, so rate limiting is a no-op.
		c := &sclient{
			ctx:     ctx,
			canMesh: true,
		}

		if err := c.rateLimit(1000); err != nil {
			t.Fatalf("mesh peer rateLimit should be no-op: %v", err)
		}
	})

	t.Run("zero_config_no_limiter", func(t *testing.T) {
		s := New(key.NewNode(), logger.Discard)
		defer s.Close()
		if !reflect.DeepEqual(s.rateConfig, RateConfig{}) {
			t.Errorf("expected zero rate limit, got %+v", s.rateConfig)
		}
	})
}

// zeroTimer returns a timer that fires immediately.
func zeroTimer(_ time.Duration) (<-chan time.Time, func() bool) {
	t := time.NewTimer(0)
	return t.C, t.Stop
}

// neverTimer returns a timer that never fires.
func neverTimer(_ time.Duration) (<-chan time.Time, func() bool) {
	return make(chan time.Time), func() bool { return false }
}

func TestRateLimitWait(t *testing.T) {
	ctx := context.Background()

	t.Run("no_wait", func(t *testing.T) {
		lim := rate.NewLimiter(10, 10)
		waited, err := rateLimitWait(ctx, lim, 5, time.Now(), zeroTimer)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if waited != 0 {
			t.Fatalf("waited = %v, want 0", waited)
		}
	})

	t.Run("wait_for_tokens", func(t *testing.T) {
		lim := rate.NewLimiter(10, 10)
		now := time.Now()
		waited, err := rateLimitWait(ctx, lim, 10, now, zeroTimer) // exhaust all tokens
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if waited != 0 {
			t.Fatalf("waited = %v, want 0", waited)
		}
		waited, err = rateLimitWait(ctx, lim, 10, now, zeroTimer)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if waited == 0 {
			t.Fatal("waited = 0, want > 0")
		}
	})

	t.Run("context_canceled", func(t *testing.T) {
		lim := rate.NewLimiter(10, 10)
		now := time.Now()
		_, err := rateLimitWait(ctx, lim, 10, now, zeroTimer) // exhaust all tokens
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		canceled, cancel := context.WithCancel(ctx) // cancel context so the select picks ctx.Done()
		cancel()
		waited, err := rateLimitWait(canceled, lim, 10, now, neverTimer) // neverTimer to only unblock via context
		if err == nil {
			t.Fatal("expected error from canceled context")
		}
		if waited != 0 {
			t.Fatalf("waited = %v, want 0", waited)
		}
	})

	t.Run("n_exceeds_burst", func(t *testing.T) {
		lim := rate.NewLimiter(10, 5)
		waited, err := rateLimitWait(ctx, lim, 10, time.Now(), zeroTimer)
		if err == nil {
			t.Fatal("expected error when n > burst")
		}
		if waited != 0 {
			t.Fatalf("waited = %v, want 0", waited)
		}
	})
}

func verifyLimiter(t *testing.T, lim *rate.Limiter, wantRateConfig RateConfig) {
	t.Helper()
	if got := lim.Limit(); got != rate.Limit(wantRateConfig.PerClientRateLimitBytesPerSec) {
		t.Errorf("client rate limit = %v; want %d", got, wantRateConfig.PerClientRateLimitBytesPerSec)
	}
	if got := lim.Burst(); got != int(wantRateConfig.PerClientRateBurstBytes) {
		t.Errorf("client burst = %v; want %d", got, wantRateConfig.PerClientRateBurstBytes)
	}
}

func TestUpdateRateLimits(t *testing.T) {
	const (
		testClientBurst1 = minRateLimitTokenBucketSize + 1
		testClientRate1  = minRateLimitTokenBucketSize + 2
		testClientBurst2 = minRateLimitTokenBucketSize + 3
		testClientRate2  = minRateLimitTokenBucketSize + 4
	)

	s := New(key.NewNode(), t.Logf)
	defer s.Close()

	// Create a non-mesh client with no initial limiter.
	clientKey := key.NewNode().Public()
	c := &sclient{
		key:     clientKey,
		s:       s,
		logf:    logger.Discard,
		canMesh: false,
	}
	cs := &clientSet{}
	cs.activeClient.Store(c)

	s.mu.Lock()
	s.clients.Store(clientKey, cs)
	s.mu.Unlock()

	rc := RateConfig{
		PerClientRateLimitBytesPerSec: testClientRate1,
		PerClientRateBurstBytes:       testClientBurst1,
	}
	s.UpdateRateLimits(rc)

	lim := c.recvLim.Load()
	if lim == nil {
		t.Fatal("expected non-nil limiter after update")
	}
	verifyLimiter(t, lim, rc)

	// Verify server fields updated.
	s.mu.Lock()
	if !reflect.DeepEqual(s.rateConfig, rc) {
		t.Errorf("s.rateConfig = %+v; want %+v", s.rateConfig, rc)
	}
	s.mu.Unlock()

	// Update again with different nonzero values.
	rc = RateConfig{
		PerClientRateLimitBytesPerSec: testClientRate2,
		PerClientRateBurstBytes:       testClientBurst2,
	}
	s.UpdateRateLimits(rc)
	lim = c.recvLim.Load()
	if lim == nil {
		t.Fatal("expected non-nil limiter")
	}
	verifyLimiter(t, lim, rc)

	// Disable rate limiting (set to 0).
	s.UpdateRateLimits(RateConfig{})

	if got := c.recvLim.Load(); got != nil {
		t.Errorf("expected nil limiter after disable, got limit=%v", got.Limit())
	}

	// Mesh peer should always have nil limiter regardless of update.
	meshKey := key.NewNode().Public()
	meshClient := &sclient{
		key:     meshKey,
		s:       s,
		logf:    logger.Discard,
		canMesh: true,
	}
	meshCS := &clientSet{}
	meshCS.activeClient.Store(meshClient)

	s.mu.Lock()
	s.clients.Store(meshKey, meshCS)
	s.mu.Unlock()

	rc = RateConfig{
		PerClientRateLimitBytesPerSec: testClientRate2,
		PerClientRateBurstBytes:       testClientBurst2,
	}
	s.UpdateRateLimits(rc)

	if got := meshClient.recvLim.Load(); got != nil {
		t.Errorf("mesh peer should have nil limiter, got limit=%v", got.Limit())
	}
	// Non-mesh client should be updated.
	lim = c.recvLim.Load()
	if lim == nil {
		t.Fatal("expected non-nil limiter for non-mesh client")
	}
	verifyLimiter(t, lim, rc)

	// Verify dup clients are also updated.
	dupKey := key.NewNode().Public()
	d1 := &sclient{key: dupKey, s: s, logf: logger.Discard}
	d2 := &sclient{key: dupKey, s: s, logf: logger.Discard}
	dupCS := &clientSet{}
	dupCS.activeClient.Store(d1)
	dupCS.dup = &dupClientSet{set: set.Of(d1, d2)}
	s.mu.Lock()
	s.clients.Store(dupKey, dupCS)
	s.mu.Unlock()

	rc = RateConfig{
		PerClientRateLimitBytesPerSec: testClientRate1,
		PerClientRateBurstBytes:       testClientBurst1,
	}
	s.UpdateRateLimits(rc)
	for i, d := range []*sclient{d1, d2} {
		dl := d.recvLim.Load()
		if dl == nil {
			t.Fatalf("dup client %d: expected non-nil limiter", i)
		}
		verifyLimiter(t, dl, rc)
	}
}

func TestLoadRateConfig(t *testing.T) {
	for _, tt := range []struct {
		name           string
		json           string
		wantRateConfig RateConfig
	}{
		{"all_set", `{"PerClientRateLimitBytesPerSec": 1, "PerClientRateBurstBytes": 2}`, RateConfig{
			PerClientRateLimitBytesPerSec: 1,
			PerClientRateBurstBytes:       2,
		}},
		{"rate_only", `{"PerClientRateLimitBytesPerSec": 1}`, RateConfig{
			PerClientRateLimitBytesPerSec: 1,
		}},
		{"zeros", `{"PerClientRateLimitBytesPerSec": 0, "PerClientRateBurstBytes": 0}`, RateConfig{}},
		{"empty_json", `{}`, RateConfig{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "rate.json")
			if err := os.WriteFile(f, []byte(tt.json), 0644); err != nil {
				t.Fatal(err)
			}
			rc, err := LoadRateConfig(f)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(rc, tt.wantRateConfig) {
				t.Errorf("rate config = %v want %v", rc, tt.wantRateConfig)
			}
		})
	}

	for _, tt := range []struct {
		name    string
		path    string
		content string // written to loaded path if non-empty; path used as-is if empty
	}{
		{"empty_path", "", ""},
		{"missing_file", filepath.Join(t.TempDir(), "nonexistent.json"), ""},
		{"invalid_json", "", "not json"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.path
			if tt.content != "" {
				path = filepath.Join(t.TempDir(), "rate.json")
				if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
					t.Fatal(err)
				}
			}
			_, err := LoadRateConfig(path)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestLoadAndApplyRateConfig(t *testing.T) {
	writeConfig := func(t *testing.T, json string) string {
		t.Helper()
		f := filepath.Join(t.TempDir(), "rate.json")
		if err := os.WriteFile(f, []byte(json), 0644); err != nil {
			t.Fatal(err)
		}
		return f
	}

	t.Run("applies_and_updates_clients", func(t *testing.T) {
		s := New(key.NewNode(), t.Logf)
		defer s.Close()

		clientKey := key.NewNode().Public()
		c := &sclient{key: clientKey, s: s, logf: logger.Discard}
		cs := &clientSet{}
		cs.activeClient.Store(c)
		s.mu.Lock()
		s.clients.Store(clientKey, cs)
		s.mu.Unlock()

		f := writeConfig(t, fmt.Sprintf(`{"PerClientRateLimitBytesPerSec": %d, "PerClientRateBurstBytes": %d}`,
			minRateLimitTokenBucketSize, minRateLimitTokenBucketSize+1))
		if err := s.LoadAndApplyRateConfig(f); err != nil {
			t.Fatalf("LoadAndApplyRateConfig: %v", err)
		}

		// Verify server fields.
		wantRateConfig := RateConfig{
			PerClientRateLimitBytesPerSec: minRateLimitTokenBucketSize,
			PerClientRateBurstBytes:       minRateLimitTokenBucketSize + 1,
		}
		s.mu.Lock()
		if !reflect.DeepEqual(s.rateConfig, wantRateConfig) {
			t.Errorf("s.rateConfig = %+v; want %+v", s.rateConfig, wantRateConfig)
		}
		s.mu.Unlock()

		// Verify client limiter.
		lim := c.recvLim.Load()
		if lim == nil {
			t.Fatal("expected non-nil limiter")
		}
		verifyLimiter(t, lim, wantRateConfig)
	})

	t.Run("burst_is_at_least_minRateLimitTokenBucketSize", func(t *testing.T) {
		s := New(key.NewNode(), t.Logf)
		defer s.Close()

		f := writeConfig(t, `{"PerClientRateLimitBytesPerSec": 1250000, "PerClientRateBurstBytes": 10}`)
		if err := s.LoadAndApplyRateConfig(f); err != nil {
			t.Fatalf("LoadAndApplyRateConfig: %v", err)
		}

		s.mu.Lock()
		gotClientBurst := s.rateConfig.PerClientRateBurstBytes
		s.mu.Unlock()
		if gotClientBurst != minRateLimitTokenBucketSize {
			t.Errorf("client burst = %d; want %d", gotClientBurst, minRateLimitTokenBucketSize)
		}
	})

	t.Run("reload_disables_limiting", func(t *testing.T) {
		s := New(key.NewNode(), t.Logf)
		defer s.Close()

		f := writeConfig(t, `{"PerClientRateLimitBytesPerSec": 1250000, "PerClientRateBurstBytes": 2500000}`)
		if err := s.LoadAndApplyRateConfig(f); err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		if reflect.DeepEqual(s.rateConfig, RateConfig{}) {
			t.Error("s.rateConfig is zero val; want nonzero rates")
		}
		s.mu.Unlock()

		if err := os.WriteFile(f, []byte(`{}`), 0644); err != nil {
			t.Fatal(err)
		}
		if err := s.LoadAndApplyRateConfig(f); err != nil {
			t.Fatal(err)
		}

		s.mu.Lock()
		if !reflect.DeepEqual(s.rateConfig, RateConfig{}) {
			t.Errorf("s.rateConfig = %+v; want %+v", s.rateConfig, RateConfig{})
		}
		s.mu.Unlock()
	})

	t.Run("propagates_errors", func(t *testing.T) {
		s := New(key.NewNode(), t.Logf)
		defer s.Close()

		if err := s.LoadAndApplyRateConfig(filepath.Join(t.TempDir(), "nonexistent.json")); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestLookupDestHashTrieFastPath(t *testing.T) {
	s := &Server{
		clientsMesh: map[key.NodePublic]PacketForwarder{},
		clock:       tstime.StdClock{},
	}
	src := pubAll(1)
	dst := pubAll(2)
	dstClient := &sclient{key: dst}
	cs := &clientSet{}
	cs.activeClient.Store(dstClient)
	s.clients.Store(dst, cs)

	c := &sclient{s: s, key: src}
	got, fwd, dstLen := c.lookupDest(dst)
	if got != dstClient || fwd != nil || dstLen != 1 {
		t.Fatalf("lookupDest = (%v, %v, %d), want (%v, nil, 1)", got, fwd, dstLen, dstClient)
	}

	// This must not deadlock while s.mu is held; the hashtrie fast path
	// should not acquire Server.mu.
	s.mu.Lock()
	got, _, _ = c.lookupDest(dst)
	s.mu.Unlock()
	if got != dstClient {
		t.Fatalf("lookupDest got %v, want %v", got, dstClient)
	}
}

func TestLookupDestHashTrieFallsBackForForwarder(t *testing.T) {
	s := &Server{
		clientsMesh: map[key.NodePublic]PacketForwarder{},
		clock:       tstime.StdClock{},
	}
	src := pubAll(1)
	dst := pubAll(2)
	c := &sclient{s: s, key: src}

	s.clientsMesh[dst] = testFwd(1)
	got, fwd, dstLen := c.lookupDest(dst)
	if got != nil || fwd != testFwd(1) || dstLen != 0 {
		t.Fatalf("lookupDest = (%v, %v, %d), want (nil, testFwd(1), 0)", got, fwd, dstLen)
	}
}

func TestLookupDestHashTrieIgnoresInactiveSet(t *testing.T) {
	s := &Server{
		clientsMesh: map[key.NodePublic]PacketForwarder{},
		clock:       tstime.StdClock{},
	}
	src := pubAll(1)
	dst := pubAll(2)
	c := &sclient{s: s, key: src}

	// A clientSet with no activeClient (a transient state during
	// register/unregister) must not be returned by the fast path.
	cs := &clientSet{}
	s.clients.Store(dst, cs)

	got, fwd, dstLen := c.lookupDest(dst)
	if got != nil || fwd != nil || dstLen != 0 {
		t.Fatalf("lookupDest with inactive set = (%v, %v, %d), want (nil, nil, 0)", got, fwd, dstLen)
	}

	// Setting activeClient on the same in-map entry must make the next
	// fast-path lookup observe it.
	newClient := &sclient{key: dst}
	cs.activeClient.Store(newClient)
	got, fwd, dstLen = c.lookupDest(dst)
	if got != newClient || fwd != nil || dstLen != 1 {
		t.Fatalf("lookupDest after activation = (%v, %v, %d), want (%v, nil, 1)", got, fwd, dstLen, newClient)
	}
}

func TestLookupDestHashTrieNoAlloc(t *testing.T) {
	s := &Server{
		clientsMesh: map[key.NodePublic]PacketForwarder{},
		clock:       tstime.StdClock{},
	}
	var dstKeys [4]key.NodePublic
	var dstClients [4]*sclient
	for i := range dstKeys {
		dstKeys[i] = pubAll(byte(i + 2))
		dstClients[i] = &sclient{key: dstKeys[i]}
		cs := &clientSet{}
		cs.activeClient.Store(dstClients[i])
		s.clients.Store(dstKeys[i], cs)
	}
	c := &sclient{s: s, key: pubAll(1)}

	var i int
	var got *sclient
	allocs := testing.AllocsPerRun(1000, func() {
		idx := i & (len(dstKeys) - 1)
		got, _, _ = c.lookupDest(dstKeys[idx])
		i++
	})
	if got == nil {
		t.Fatal("lookupDest returned nil")
	}
	if allocs != 0 {
		t.Fatalf("lookupDest allocated %v times per run, want 0", allocs)
	}
}

func BenchmarkLookupDestHashTrie(b *testing.B) {
	s := &Server{
		clientsMesh: map[key.NodePublic]PacketForwarder{},
		clock:       tstime.StdClock{},
	}
	var dstKeys [4]key.NodePublic
	var dstClients [4]*sclient
	for i := range dstKeys {
		dstKeys[i] = pubAll(byte(i + 2))
		dstClients[i] = &sclient{key: dstKeys[i]}
		cs := &clientSet{}
		cs.activeClient.Store(dstClients[i])
		s.clients.Store(dstKeys[i], cs)
	}

	b.ReportAllocs()
	b.SetParallelism(32)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		c := &sclient{s: s, key: pubAll(1)}
		var i int
		for pb.Next() {
			idx := i & (len(dstKeys) - 1)
			got, fwd, dstLen := c.lookupDest(dstKeys[idx])
			if got != dstClients[idx] || fwd != nil {
				b.Fatalf("lookupDest = (%v, %v, %d), want (%v, nil, _)", got, fwd, dstLen, dstClients[idx])
			}
			i++
		}
	})
}

func BenchmarkSenderCardinalityOverhead(b *testing.B) {
	hll := hyperloglog.New()
	sender := key.NewNode().Public()

	b.Run("WithTracking", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if hll != nil {
				hll.Insert(sender.AppendTo(nil))
			}
		}
	})

	b.Run("WithoutTracking", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = sender.AppendTo(nil)
		}
	})
}

func TestPktQueue(t *testing.T) {
	mkpkt := func(i int) pkt { return pkt{bs: []byte{byte(i)}} }
	src := key.NewNode().Public()

	t.Run("fifo_and_pool", func(t *testing.T) {
		s := New(key.NewNode(), t.Logf)
		defer s.Close()
		s.perClientSendQueueDepth = 3

		var q pktQueue
		if _, more, ok := q.dequeue(s); ok || more {
			t.Fatal("dequeue on empty queue reported ok or more")
		}
		for i := range 3 {
			dropped, wasEmpty, ok := q.enqueue(s, mkpkt(i))
			if !ok || dropped.bs != nil {
				t.Fatalf("enqueue %d: ok=%v dropped=%v", i, ok, dropped.bs)
			}
			// Only the first enqueue finds the queue empty.
			if want := i == 0; wasEmpty != want {
				t.Errorf("enqueue %d: wasEmpty=%v, want %v", i, wasEmpty, want)
			}
		}
		if q.ring == nil {
			t.Fatal("ring not allocated after enqueue")
		}
		// Full: the head (0) is dropped to make room for 3.
		dropped, wasEmpty, ok := q.enqueue(s, mkpkt(3))
		if !ok || string(dropped.bs) != "\x00" {
			t.Fatalf("enqueue on full queue: ok=%v dropped=%q, want head 0 dropped", ok, dropped.bs)
		}
		if wasEmpty {
			t.Error("enqueue on full queue reported wasEmpty")
		}
		var got []byte
		for {
			p, more, ok := q.dequeue(s)
			if !ok {
				break
			}
			got = append(got, p.bs...)
			if wantMore := len(got) < 3; more != wantMore {
				t.Errorf("dequeue %d: more=%v, want %v", len(got), more, wantMore)
			}
		}
		if want := "\x01\x02\x03"; string(got) != want {
			t.Errorf("dequeued %q, want %q", got, want)
		}
		if q.ring != nil {
			t.Error("ring not released to the pool after draining")
		}
		// The ring should have gone back to the pool with no
		// packets still referenced from it.
		if ring, ok := s.sendQueueRingPool.Get().(*[]pkt); ok {
			for i, p := range *ring {
				if p.bs != nil {
					t.Errorf("pooled ring slot %d still holds a packet", i)
				}
			}
		}
	})

	t.Run("close", func(t *testing.T) {
		s := New(key.NewNode(), t.Logf)
		defer s.Close()
		s.perClientSendQueueDepth = 4

		var q pktQueue
		q.enqueue(s, pkt{bs: []byte("a"), src: src})
		q.enqueue(s, pkt{bs: []byte("b"), src: src})
		var dropped []string
		q.close(s, func(p pkt) { dropped = append(dropped, string(p.bs)) })
		if want := []string{"a", "b"}; !slices.Equal(dropped, want) {
			t.Errorf("close dropped %q, want %q", dropped, want)
		}
		if q.ring != nil {
			t.Error("ring not released on close")
		}
		if _, _, ok := q.enqueue(s, mkpkt(0)); ok {
			t.Error("enqueue after close succeeded")
		}
		if q.ring != nil {
			t.Error("enqueue after close allocated a ring")
		}
	})

	// A Server that didn't come from New (as some unit tests build)
	// has no configured queue depth and an unprimed pool. Enqueues must
	// fail cleanly rather than panic on a nil pool.Get result, and must
	// not allocate.
	t.Run("zero_server", func(t *testing.T) {
		s := &Server{}
		var q pktQueue
		if _, _, ok := q.enqueue(s, mkpkt(0)); ok {
			t.Error("enqueue on zero-depth queue succeeded")
		}
		if q.ring != nil {
			t.Error("zero-depth enqueue allocated a ring")
		}
		if _, _, ok := q.dequeue(s); ok {
			t.Error("dequeue on zero-depth queue reported ok")
		}
		q.close(s, func(pkt) { t.Error("close on empty queue dropped a packet") })
	})
}

// TestSendPktHeadDropAttribution checks that when a full queue drops
// its head packet to make room, the drop is attributed to that
// packet's sender, not to the sender of the packet that displaced it.
func TestSendPktHeadDropAttribution(t *testing.T) {
	var logMu sync.Mutex
	var logs []string
	s := New(key.NewNode(), func(format string, args ...any) {
		logMu.Lock()
		defer logMu.Unlock()
		logs = append(logs, fmt.Sprintf(format, args...))
	})
	defer s.Close()
	s.perClientSendQueueDepth = 1

	dst := &sclient{s: s, key: key.NewNode().Public()}
	dst.writerState.Store(packWriterState(writerStopped, 0)) // no conn to write to; sendPkt's wake is a no-op
	first := &sclient{s: s, key: key.NewNode().Public()}
	second := &sclient{s: s, key: key.NewNode().Public()}

	// Drops to dst are logged verbosely, with the source key.
	verboseDropKeys[dst.key] = true
	defer delete(verboseDropKeys, dst.key)

	if err := first.sendPkt(dst, pkt{bs: []byte("first"), src: first.key}); err != nil {
		t.Fatal(err)
	}
	if err := second.sendPkt(dst, pkt{bs: []byte("second"), src: second.key}); err != nil {
		t.Fatal(err)
	}

	logMu.Lock()
	defer logMu.Unlock()
	want := fmt.Sprintf("drop (%s) %s -> %s", first.key.ShortString(), dropReasonQueueHead, dst.key.ShortString())
	if !slices.Contains(logs, want) {
		t.Errorf("logs = %q; want to contain %q", logs, want)
	}
}

// gatedConn is a derp.Conn whose Writes block until the test releases
// them, one at a time, so a test can hold the writer inside a Flush.
type gatedConn struct {
	writes chan int      // receives len(p) as each Write begins
	gate   chan struct{} // each Write completes on receiving from it
	closed chan struct{} // closed by Close
	once   sync.Once
}

func newGatedConn() *gatedConn {
	return &gatedConn{
		writes: make(chan int, 16),
		gate:   make(chan struct{}),
		closed: make(chan struct{}),
	}
}

func (c *gatedConn) Write(p []byte) (int, error) {
	c.writes <- len(p)
	select {
	case <-c.gate:
		return len(p), nil
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *gatedConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *gatedConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *gatedConn) SetDeadline(time.Time) error      { return nil }
func (c *gatedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *gatedConn) SetWriteDeadline(time.Time) error { return nil }

// TestWriterBufferedWriteFrames checks that the bufferedWriteFrames
// histogram counts exactly the frames written per flush. In
// particular a writer pass that itself writes nothing must not
// inflate the count of the batch that follows it.
func TestWriterBufferedWriteFrames(t *testing.T) {
	s := New(key.NewNode(), t.Logf)
	defer s.Close()

	conn := newGatedConn()
	c := &sclient{
		s:    s,
		key:  key.NewNode().Public(),
		nc:   conn,
		bw:   &lazyBufioWriter{w: conn},
		logf: t.Logf,
	}
	c.runWriterFunc = c.runWriter

	src := key.NewNode().Public()
	send := func(n int) {
		for range n {
			if err := c.sendPkt(c, pkt{bs: []byte("hello"), src: src}); err != nil {
				t.Fatalf("sendPkt: %v", err)
			}
		}
	}
	// awaitWrite waits for the writer to be blocked in a Write, which
	// happens only from Flush.
	awaitWrite := func() {
		t.Helper()
		select {
		case <-conn.writes:
		case <-time.After(10 * time.Second):
			t.Fatal("timeout waiting for the writer to flush")
		}
	}
	release := func() { conn.gate <- struct{}{} }

	// One packet: it wakes a writer, which writes it and blocks
	// flushing it.
	send(1)
	awaitWrite()

	// While it's blocked, queue a batch. Its wake sets a pending bit
	// on the running writer, so after the first flush's observation
	// the writer's park attempt fails and it drains again, without an
	// observation for the wake itself.
	const batch = 5
	send(batch)
	release()

	// The batch is drained in one pass and flushed.
	awaitWrite()
	release()

	// The writer has parked, or is about to. A pong wakes it again
	// for one more write and flush; once that Write has begun, the
	// batch's observation has been recorded.
	c.queuePong([8]byte{})
	awaitWrite()

	var h map[string]float64
	if err := json.Unmarshal([]byte(s.bufferedWriteFrames.String()), &h); err != nil {
		t.Fatal(err)
	}
	// The buckets are cumulative, so the number of observations of
	// exactly v is bucket[v] minus bucket[v-1].
	exactly := func(v int) float64 { return h[strconv.Itoa(v)] - h[strconv.Itoa(v-1)] }
	if h["count"] != 2 || exactly(1) != 1 || exactly(batch) != 1 {
		t.Errorf("histogram = %v; want exactly two observations, one of 1 and one of %d", h, batch)
	}

	release()
	c.stopWriter()
	if c.writeErr != nil {
		t.Errorf("writer: %v", c.writeErr)
	}
	if got := c.writerState.Load(); got.phase() != writerStopped {
		t.Errorf("writer phase = %d; want writerStopped (%d)", got.phase(), writerStopped)
	}
}

// TestSenderCardinalityEnv checks that the writer keeps a unique sender
// estimate only when TS_DERP_SENDER_CARDINALITY is set.
func TestSenderCardinalityEnv(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%v", enabled), func(t *testing.T) {
			envVal := ""
			if enabled {
				envVal = "1"
			}
			t.Setenv("TS_DERP_SENDER_CARDINALITY", envVal)
			s := New(key.NewNode(), t.Logf)
			defer s.Close()
			if s.trackSenderCardinality != enabled {
				t.Fatalf("trackSenderCardinality = %v; want %v", s.trackSenderCardinality, enabled)
			}

			conn := newGatedConn()
			c := &sclient{
				s:    s,
				key:  key.NewNode().Public(),
				nc:   conn,
				bw:   &lazyBufioWriter{w: conn},
				logf: t.Logf,
			}
			c.runWriterFunc = c.runWriter

			// Send one packet at a time from distinct sources, waiting
			// for each to reach the conn so its insert has happened.
			const numSenders = 10
			for range numSenders {
				if err := c.sendPkt(c, pkt{bs: []byte("hello"), src: key.NewNode().Public()}); err != nil {
					t.Fatalf("sendPkt: %v", err)
				}
				select {
				case <-conn.writes:
				case <-time.After(10 * time.Second):
					t.Fatal("timeout waiting for the writer to flush")
				}
				conn.gate <- struct{}{}
			}

			got := c.EstimatedUniqueSenders()
			if !enabled {
				if got != 0 {
					t.Errorf("EstimatedUniqueSenders() = %d; want 0 when disabled", got)
				}
			} else if got < numSenders-2 || got > numSenders+2 {
				t.Errorf("EstimatedUniqueSenders() = %d; want ~%d", got, numSenders)
			}

			c.stopWriter()
			if c.writeErr != nil {
				t.Errorf("writer: %v", c.writeErr)
			}
		})
	}
}

func TestPacketBufPool(t *testing.T) {
	s := &Server{}

	// smallestClass is the reference implementation of packetBufClass:
	// the index of the smallest power-of-two class that holds n bytes.
	smallestClass := func(n int) int {
		for i := range numPacketBufClasses {
			if n <= 1<<(packetBufMinClass+i) {
				return i
			}
		}
		t.Fatalf("no size class holds %d bytes", n)
		return -1
	}
	for n := 0; n <= derp.MaxPacketSize; n++ {
		got, ok := packetBufClass(n)
		if want := smallestClass(n); !ok || got != want {
			t.Fatalf("packetBufClass(%d) = %d, %v; want %d, true", n, got, ok, want)
		}
	}
	for _, n := range []int{-1, derp.MaxPacketSize + 1} {
		if _, ok := packetBufClass(n); ok {
			t.Errorf("packetBufClass(%d) ok = true; want false", n)
		}
	}

	// Exercise get/put at the bounds of every size class.
	for class := range numPacketBufClasses {
		size := 1 << (packetBufMinClass + class)
		lo := 0
		if class > 0 {
			lo = size/2 + 1
		}
		for _, n := range []int{lo, lo + 1, size - 1, size} {
			buf := s.getPacketBuf(n)
			if len(*buf) != n {
				t.Errorf("getPacketBuf(%d): len = %d", n, len(*buf))
			}
			if cap(*buf) != size {
				t.Errorf("getPacketBuf(%d): cap = %d; want class %d size %d", n, cap(*buf), class, size)
			}
			s.putPacketBuf(buf)
		}
	}
	s.putPacketBuf(nil) // no-op for pkts whose bs didn't come from the pool

	if allocs := testing.AllocsPerRun(1000, func() {
		s.putPacketBuf(s.getPacketBuf(700))
	}); allocs != 0 {
		t.Errorf("get/put cycle allocates %v times per run; want 0", allocs)
	}

	mustPanic := func(name string, f func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s: did not panic", name)
			}
		}()
		f()
	}
	mustPanic("getPacketBuf(-1)", func() { s.getPacketBuf(-1) })
	mustPanic("getPacketBuf(MaxPacketSize+1)", func() { s.getPacketBuf(derp.MaxPacketSize + 1) })
	for _, c := range []int{0, 3, 1<<packetBufMinClass - 1, 1<<packetBufMinClass + 1, 1500, 2 * derp.MaxPacketSize} {
		b := make([]byte, c)
		mustPanic(fmt.Sprintf("putPacketBuf(cap %d)", c), func() { s.putPacketBuf(&b) })
	}
}

// frameSeqConn is a derp.Conn that parses the DERP frames written to
// it. It expects each packet frame's payload to end in a big-endian
// uint32 sequence number, and records the highest one written before
// the first pong.
type frameSeqConn struct {
	mu           sync.Mutex
	partial      []byte // bytes of a frame not yet fully written
	packets      int    // packet frames written
	maxSeq       uint32 // highest sequence number written
	pongs        int    // pong frames written
	maxSeqAtPong uint32 // maxSeq when the first pong was written
}

func (c *frameSeqConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.partial = append(c.partial, p...)
	for len(c.partial) >= derp.FrameHeaderLen {
		ft := derp.FrameType(c.partial[0])
		fl := int(binary.BigEndian.Uint32(c.partial[1:derp.FrameHeaderLen]))
		if len(c.partial) < derp.FrameHeaderLen+fl {
			break
		}
		payload := c.partial[derp.FrameHeaderLen : derp.FrameHeaderLen+fl]
		switch ft {
		case derp.FrameRecvPacket:
			c.packets++
			c.maxSeq = max(c.maxSeq, binary.BigEndian.Uint32(payload[len(payload)-4:]))
		case derp.FramePong:
			if c.pongs == 0 {
				c.maxSeqAtPong = c.maxSeq
			}
			c.pongs++
		}
		c.partial = c.partial[derp.FrameHeaderLen+fl:]
	}
	return len(p), nil
}

func (c *frameSeqConn) stats() (packets, pongs int, maxSeqAtPong uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.packets, c.pongs, c.maxSeqAtPong
}

func (c *frameSeqConn) Close() error                     { return nil }
func (c *frameSeqConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *frameSeqConn) SetDeadline(time.Time) error      { return nil }
func (c *frameSeqConn) SetReadDeadline(time.Time) error  { return nil }
func (c *frameSeqConn) SetWriteDeadline(time.Time) error { return nil }

// TestWriterFloodDoesNotStarveControlFrames checks that a sender
// keeping a client's send queue topped up can't hold the writer in its
// packet drain forever: a pong queued during the flood is written
// after at most a queue's depth worth of the packets enqueued after it.
func TestWriterFloodDoesNotStarveControlFrames(t *testing.T) {
	s := New(key.NewNode(), t.Logf)
	defer s.Close()
	depth := uint32(s.perClientSendQueueDepth)

	conn := &frameSeqConn{}
	c := &sclient{
		s:    s,
		key:  key.NewNode().Public(),
		nc:   conn,
		bw:   &lazyBufioWriter{w: conn},
		logf: t.Logf,
	}
	c.runWriterFunc = c.runWriter

	// Flood the queue from another goroutine, faster than the writer
	// drains it, so dequeue always reports more packets behind. Each
	// packet carries its sequence number.
	var seq atomic.Uint32
	stop := make(chan struct{})
	var wg sync.WaitGroup
	src := key.NewNode().Public()
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			var bs [4]byte
			binary.BigEndian.PutUint32(bs[:], seq.Add(1))
			if err := c.sendPkt(c, pkt{bs: bs[:], src: src}); err != nil {
				t.Errorf("sendPkt: %v", err)
				return
			}
		}
	})
	defer func() {
		close(stop)
		wg.Wait()
		c.stopWriter()
	}()

	waitFor := func(what string, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for !ok() {
			if time.Now().After(deadline) {
				t.Fatalf("timeout waiting for %s", what)
			}
			time.Sleep(time.Millisecond)
		}
	}
	// Let the flood get well past one queue's depth so the writer is
	// surely in its drain loop.
	waitFor("the flood to get going", func() bool {
		packets, _, _ := conn.stats()
		return packets >= 4*int(depth)
	})

	c.queuePong([8]byte{'p', 'o', 'n', 'g'})
	seqAtPong := seq.Load()
	waitFor("the pong to be written", func() bool {
		_, pongs, _ := conn.stats()
		return pongs > 0
	})
	// The pass in progress may finish its budget of depth packets
	// first, and then the pong goes out before the next pass's packets,
	// so at most depth packets enqueued after the pong precede it.
	_, _, maxSeqAtPong := conn.stats()
	if maxSeqAtPong > seqAtPong+depth {
		t.Errorf("pong written after packet %d; want no later than packet %d (pong queued at %d, depth %d)", maxSeqAtPong, seqAtPong+depth, seqAtPong, depth)
	}
}

// writerTestClient is a DERP client connected over TCP loopback to an
// in-process Server, for tests of the server's per-client writer.
type writerTestClient struct {
	c      *derp.Client
	nc     net.Conn
	key    key.NodePrivate
	cancel context.CancelFunc
}

// newWriterTestClient connects a new client to s. Its Accept goroutine
// is the connection's reader; the test's caller owns the client side.
func newWriterTestClient(t *testing.T, s *Server, ln net.Listener) *writerTestClient {
	t.Helper()
	connOut, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	connIn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	brwServer := bufio.NewReadWriter(bufio.NewReader(connIn), bufio.NewWriter(connIn))
	go s.Accept(ctx, connIn, brwServer, connIn.RemoteAddr().String())

	k := key.NewNode()
	brw := bufio.NewReadWriter(bufio.NewReader(connOut), bufio.NewWriter(connOut))
	c, err := derp.NewClient(k, connOut, brw, logger.Discard)
	if err != nil {
		cancel()
		t.Fatalf("client: %v", err)
	}
	return &writerTestClient{c: c, nc: connOut, key: k, cancel: cancel}
}

func (tc *writerTestClient) close() {
	tc.nc.Close()
	tc.cancel()
}

// sendToSelf sends a packet to the client itself and waits to receive
// it back, exercising the server's writer for that client.
func (tc *writerTestClient) sendToSelf(t *testing.T, payload []byte) {
	t.Helper()
	if err := tc.c.Send(tc.key.Public(), payload); err != nil {
		t.Fatalf("Send: %v", err)
	}
	for {
		tc.nc.SetReadDeadline(time.Now().Add(10 * time.Second))
		m, err := tc.c.Recv()
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		if rp, ok := m.(derp.ReceivedPacket); ok {
			if !bytes.Equal(rp.Data, payload) {
				t.Fatalf("got packet %q; want %q", rp.Data, payload)
			}
			return
		}
	}
}

// awaitGoroutines waits for the process's goroutine count to settle at
// want, tolerating transient goroutines such as timer callbacks.
func awaitGoroutines(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		got := runtime.NumGoroutine()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			t.Fatalf("goroutines = %d; want %d\n%s", got, want, buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestWriterParksWhenIdle locks in that an idle connection costs the
// server exactly one goroutine, its reader, both when it has never
// been written to and after its writer has run and parked again.
func TestWriterParksWhenIdle(t *testing.T) {
	s := New(key.NewNode(), t.Logf)
	defer s.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	base := runtime.NumGoroutine()

	const numClients = 20
	var clients []*writerTestClient
	for range numClients {
		clients = append(clients, newWriterTestClient(t, s, ln))
	}
	defer func() {
		for _, tc := range clients {
			tc.close()
		}
	}()
	// Accepting a client also handed it its ServerInfo frame, so the
	// writer ran once already. It must have parked.
	awaitGoroutines(t, base+numClients)

	for i, tc := range clients {
		tc.sendToSelf(t, []byte(strconv.Itoa(i)))
	}
	awaitGoroutines(t, base+numClients)

	for _, tc := range clients {
		tc.close()
	}
	clients = nil
	awaitGoroutines(t, base)
}

// TestWriterWakeStress races the writer's park decision against
// producers on several goroutines and checks that nothing is lost:
// every packet, sent one at a time so the writer parks between them,
// and every peer gone request, which the writer must deliver exactly.
func TestWriterWakeStress(t *testing.T) {
	s := New(key.NewNode(), logger.Discard)
	defer s.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	tc := newWriterTestClient(t, s, ln)
	defer tc.close()

	var sc *sclient
	for deadline := time.Now().Add(10 * time.Second); sc == nil; {
		if set, ok := s.clients.Load(tc.key.Public()); ok {
			sc = set.activeClient.Load()
		}
		if time.Now().After(deadline) {
			t.Fatal("client never registered")
		}
	}

	const (
		producers      = 4
		gonePerProd    = 500
		packets        = 500
		wantGone       = producers * gonePerProd
		wantPacketData = "hi"
	)
	gonePeer := key.NewNode().Public()
	var wg sync.WaitGroup
	for range producers {
		wg.Go(func() {
			for range gonePerProd {
				sc.requestPeerGoneWrite(gonePeer, derp.PeerGoneReasonDisconnected)
			}
		})
	}

	gotGone, gotPackets := 0, 0
	sent := 0
	if err := tc.c.Send(tc.key.Public(), []byte(wantPacketData)); err != nil {
		t.Fatal(err)
	}
	sent++
	for gotGone < wantGone || gotPackets < packets {
		tc.nc.SetReadDeadline(time.Now().Add(30 * time.Second))
		m, err := tc.c.Recv()
		if err != nil {
			t.Fatalf("Recv after %d gone, %d packets: %v", gotGone, gotPackets, err)
		}
		switch m := m.(type) {
		case derp.PeerGoneMessage:
			if m.Peer != gonePeer {
				t.Fatalf("PeerGone for %v; want %v", m.Peer, gonePeer)
			}
			gotGone++
		case derp.ReceivedPacket:
			if string(m.Data) != wantPacketData {
				t.Fatalf("packet %q; want %q", m.Data, wantPacketData)
			}
			gotPackets++
			if sent < packets {
				// Each packet goes out only once the previous one
				// came back, so the writer had a chance to park in
				// between.
				if err := tc.c.Send(tc.key.Public(), []byte(wantPacketData)); err != nil {
					t.Fatal(err)
				}
				sent++
			}
		}
	}
	wg.Wait()
}
