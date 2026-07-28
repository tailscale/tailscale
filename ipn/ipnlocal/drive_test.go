// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_drive

package ipnlocal

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/studio-b12/gowebdav"
	"tailscale.com/control/controlclient"
	"tailscale.com/drive"
	"tailscale.com/drive/driveimpl"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/set"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter/filtertype"
)

// TestDriveTransportRoundTrip_NetworkError tests that driveTransport.RoundTrip
// doesn't panic when the underlying transport returns a nil response with an
// error.
//
// See: https://github.com/tailscale/tailscale/issues/17306
func TestDriveTransportRoundTrip_NetworkError(t *testing.T) {
	b := newTestLocalBackend(t)

	testErr := errors.New("network connection failed")
	mockTransport := &mockRoundTripper{
		err: testErr,
	}
	dt := &driveTransport{
		b:  b,
		tr: mockTransport,
	}

	req := httptest.NewRequest("GET", "http://100.64.0.1:1234/some/path", nil)
	resp, err := dt.RoundTrip(req)
	if err == nil {
		t.Fatal("got nil error, expected non-nil")
	} else if !errors.Is(err, testErr) {
		t.Errorf("got error %v, expected %v", err, testErr)
	}
	if resp != nil {
		t.Errorf("wanted nil response, got %v", resp)
	}
}

type mockRoundTripper struct {
	err error
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, m.err
}

// TestDriveGenBumps verifies that driveGen increments at each of the three
// call sites the [driveRemoteSource] cache invalidation depends on:
// full netmap installs, netmap deltas, and packet-filter updates. If any of
// these stops bumping, WebDAV clients would see a stale remote list until
// some other event happened to bump the counter, so the test asserts each
// site independently.
func TestDriveGenBumps(t *testing.T) {
	b := newTestLocalBackend(t)

	assertBumped := func(name string, fn func()) {
		t.Helper()
		before := b.driveGen.Load()
		fn()
		after := b.driveGen.Load()
		if after <= before {
			t.Errorf("%s: driveGen = %d after, %d before; want strictly greater", name, after, before)
		}
	}

	selfNode := (&tailcfg.Node{
		ID:        1,
		Key:       makeNodeKeyFromID(1),
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
	}).View()
	peer2 := (&tailcfg.Node{
		ID:        2,
		Key:       makeNodeKeyFromID(2),
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
	}).View()

	assertBumped("setNetMapLocked", func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.setNetMapLocked(&netmap.NetworkMap{
			SelfNode: selfNode,
			Peers:    []tailcfg.NodeView{peer2},
		})
	})

	assertBumped("UpdateNetmapDelta", func() {
		muts, ok := netmap.MutationsFromMapResponse(&tailcfg.MapResponse{
			OnlineChange: map[tailcfg.NodeID]bool{peer2.ID(): true},
		}, time.Time{})
		if !ok {
			t.Fatal("MutationsFromMapResponse failed")
		}
		if !b.UpdateNetmapDelta(muts) {
			t.Fatal("UpdateNetmapDelta returned false")
		}
	})

	assertBumped("UpdatePacketFilter", func() {
		if !b.UpdatePacketFilter(views.Slice[tailcfg.FilterRule]{}, nil) {
			t.Fatal("UpdatePacketFilter returned false")
		}
	})
}

// TestDriveRemoteSourceAccessGate verifies that [driveRemoteSource.Remotes]
// yields zero entries when the self node lacks NodeAttrsTaildriveAccess, and
// the full peer set when it has it. This is the only path that decides
// whether the local Taildrive root shows any folders at all, so a regression
// here would silently break access for every user.
func TestDriveRemoteSourceAccessGate(t *testing.T) {
	b := newTestLocalBackend(t)

	selfNode := (&tailcfg.Node{
		ID:        1,
		Key:       makeNodeKeyFromID(1),
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
	}).View()
	peers := []tailcfg.NodeView{
		(&tailcfg.Node{
			ID:        2,
			Key:       makeNodeKeyFromID(2),
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		}).View(),
		(&tailcfg.Node{
			ID:        3,
			Key:       makeNodeKeyFromID(3),
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")},
		}).View(),
	}

	install := func(allCaps set.Set[tailcfg.NodeCapability]) {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.setNetMapLocked(&netmap.NetworkMap{
			SelfNode: selfNode,
			Peers:    peers,
			AllCaps:  allCaps,
		})
	}

	src := driveRemoteSource{b: b}
	collect := func() []*drive.Remote {
		var out []*drive.Remote
		for r := range src.Remotes() {
			out = append(out, r)
		}
		return out
	}

	install(nil)
	if got := collect(); len(got) != 0 {
		t.Errorf("Remotes without DriveAccess cap: got %d entries, want 0", len(got))
	}

	install(set.Of(tailcfg.NodeAttrsTaildriveAccess))
	if got := collect(); len(got) != len(peers) {
		t.Errorf("Remotes with DriveAccess cap: got %d entries, want %d", len(got), len(peers))
	}
}

// captureFS wraps a real [drive.FileSystemForLocal] but records the most
// recent [drive.RemoteSource] installed via SetRemoteSource. It lets the
// test below observe what NewLocalBackend wires up without poking at
// LocalBackend internals.
type captureFS struct {
	drive.FileSystemForLocal

	mu     sync.Mutex
	source drive.RemoteSource
}

func (c *captureFS) SetRemoteSource(source drive.RemoteSource) {
	c.mu.Lock()
	c.source = source
	c.mu.Unlock()
	c.FileSystemForLocal.SetRemoteSource(source)
}

func (c *captureFS) lastSource() drive.RemoteSource {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.source
}

// TestDriveRemoteSourceInstalled verifies that NewLocalBackend wires a
// [driveRemoteSource] into sys.DriveForLocal via the
// hookInstallDriveRemoteSource init hook. Without this wiring, every
// remote-set update would silently no-op because the filesystem would
// have no source to pull from.
func TestDriveRemoteSourceInstalled(t *testing.T) {
	bus := eventbustest.NewBus(t)
	sys := tsd.NewSystemWithBus(bus)
	cf := &captureFS{FileSystemForLocal: driveimpl.NewFileSystemForLocal(logger.Discard)}
	sys.Set(drive.FileSystemForLocal(cf))
	t.Cleanup(func() { cf.FileSystemForLocal.Close() })

	b := newTestLocalBackendWithSys(t, sys)

	src := cf.lastSource()
	if src == nil {
		t.Fatal("SetRemoteSource was never called on FileSystemForLocal")
	}
	drs, ok := src.(driveRemoteSource)
	if !ok {
		t.Fatalf("installed source is %T, want driveRemoteSource", src)
	}
	if drs.b != b {
		t.Errorf("driveRemoteSource.b = %p, want LocalBackend %p", drs.b, b)
	}
}

// driveEndToEndHarness wires up:
//
//   - a real [LocalBackend] backed by a mock controlclient, so a full netmap
//     can be delivered through the same code path the real controlclient
//     uses (SetControlClientStatus → setNetMapLocked → updateFilterLocked);
//
//   - a real [driveimpl.FileSystemForLocal] injected into [tsd.System]
//     before NewLocalBackend, so installDriveRemoteSource fires; and
//
//   - a TCP listener that hands accepted connections to fs.HandleConn,
//     plus a gowebdav client pointed at it, so WebDAV PROPFINDs traverse
//     the same code path a real Mac/Windows client would.
type driveEndToEndHarness struct {
	t      *testing.T
	b      *LocalBackend
	cc     *mockControl
	fs     drive.FileSystemForLocal
	client *gowebdav.Client
	domain string

	selfAddr netip.Addr // self IPv4 single-IP address

	// wg tracks the listener's accept loop and every per-connection
	// fs.HandleConn goroutine, so t.Cleanup can Wait for them after
	// closing the listener and prevent goroutine leaks across tests.
	wg sync.WaitGroup
}

func newDriveEndToEndHarness(t *testing.T) *driveEndToEndHarness {
	bus := eventbustest.NewBus(t)
	sys := tsd.NewSystemWithBus(bus)

	logf := logger.Discard
	sys.Set(new(mem.Store))
	eng, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
	if err != nil {
		t.Fatalf("NewFakeUserspaceEngine: %v", err)
	}
	t.Cleanup(eng.Close)
	sys.Set(eng)

	fs := driveimpl.NewFileSystemForLocal(logf)
	sys.Set(drive.FileSystemForLocal(fs))
	t.Cleanup(func() { fs.Close() })

	b := newLocalBackendWithSysAndTestControl(t, false, sys, func(tb testing.TB, opts controlclient.Options) controlclient.Client {
		return newClient(tb, opts)
	})
	if err := b.Start(ipn.Options{}); err != nil {
		t.Fatalf("(*LocalBackend).Start: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}

	client := gowebdav.NewClient(fmt.Sprintf("http://%s", ln.Addr()), "", "")
	client.SetTransport(&http.Transport{DisableKeepAlives: true})

	h := &driveEndToEndHarness{
		t:        t,
		b:        b,
		cc:       b.cc.(*mockControl),
		fs:       fs,
		client:   client,
		domain:   "example.com",
		selfAddr: netip.MustParseAddr("100.64.0.1"),
	}

	t.Cleanup(h.wg.Wait) // runs last, after ln.Close etc
	t.Cleanup(func() { ln.Close() })

	h.wg.Go(func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			h.wg.Go(func() { fs.HandleConn(conn, conn.RemoteAddr()) })
		}
	})

	return h
}

// peerSpec describes a peer to be installed in a test netmap.
// driveCap controls whether the packet filter is built with a rule that
// grants the peer the [tailcfg.PeerCapabilityTaildriveSharer] cap to self.
type peerSpec struct {
	id       tailcfg.NodeID
	name     string
	addr     netip.Addr
	online   bool
	driveCap bool
	peerAPI  bool
}

func (s peerSpec) node() *tailcfg.Node {
	n := &tailcfg.Node{
		ID:        s.id,
		Name:      s.name + ".example.com.",
		Key:       makeNodeKeyFromID(s.id),
		Addresses: []netip.Prefix{netip.PrefixFrom(s.addr, s.addr.BitLen())},
		Online:    new(s.online),
	}
	if s.peerAPI {
		hi := &tailcfg.Hostinfo{
			Services: []tailcfg.Service{{
				Proto: tailcfg.PeerAPI4,
				Port:  12345,
			}},
		}
		n.Hostinfo = hi.View()
	}
	// The controlclient calls InitDisplayNames before delivering peers to
	// LocalBackend. The mockControl path used here skips that step, so we
	// do it explicitly to get DisplayName(false) → ComputedName ("alpha"
	// etc.) rather than the node-key fallback.
	n.InitDisplayNames("example.com")
	return n
}

// filterMatchesFor builds the parsed packet-filter matches that grant
// PeerCapabilityTaildriveSharer from each driveCap-enabled peer's address
// to the self address. PeerHasCap reads its result, so this is what flips a
// peer in or out of the drive-capable set in the e2e test.
func (h *driveEndToEndHarness) filterMatchesFor(specs []peerSpec) []filtertype.Match {
	var matches []filtertype.Match
	for _, s := range specs {
		if !s.driveCap {
			continue
		}
		matches = append(matches, filtertype.Match{
			IPProto: views.SliceOf([]ipproto.Proto{ipproto.TCP}),
			Srcs:    []netip.Prefix{netip.PrefixFrom(s.addr, s.addr.BitLen())},
			Caps: []filtertype.CapMatch{{
				Dst: netip.PrefixFrom(h.selfAddr, h.selfAddr.BitLen()),
				Cap: tailcfg.PeerCapabilityTaildriveSharer,
			}},
		})
	}
	return matches
}

// installNetMap pushes a netmap built from specs through the mock control
// client. The self node always has Addresses and NodeAttrsTaildriveAccess
// in AllCaps. The packet filter is generated to grant
// PeerCapabilityTaildriveSharer from each driveCap-enabled peer's IP to
// the self IP.
func (h *driveEndToEndHarness) installNetMap(specs []peerSpec) {
	h.t.Helper()
	peers := make([]tailcfg.NodeView, 0, len(specs))
	for _, s := range specs {
		peers = append(peers, s.node().View())
	}
	nm := &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			ID:        1,
			Name:      "self.example.com.",
			Key:       makeNodeKeyFromID(1),
			Addresses: []netip.Prefix{netip.PrefixFrom(h.selfAddr, h.selfAddr.BitLen())},
		}).View(),
		Domain:       h.domain,
		Peers:        peers,
		AllCaps:      set.Of(tailcfg.NodeAttrsTaildriveAccess),
		PacketFilter: h.filterMatchesFor(specs),
	}
	h.cc.send(sendOpt{loginFinished: true, nm: nm})
}

// sendMapResponse turns a [tailcfg.MapResponse] into a slice of
// [netmap.NodeMutation] via netmap.MutationsFromMapResponse — the same path
// the real controlclient uses on the incremental-fast-path — and dispatches
// it through [LocalBackend.UpdateNetmapDelta]. Going through MapResponse
// rather than constructing NodeMutation values directly keeps the test
// honest about wire-shaped inputs: every mutation kind exercised here is
// reachable by the control server with no test-only constructs.
func (h *driveEndToEndHarness) sendMapResponse(mr *tailcfg.MapResponse) {
	h.t.Helper()
	muts, ok := netmap.MutationsFromMapResponse(mr, time.Time{})
	if !ok {
		h.t.Fatalf("MutationsFromMapResponse(%+v) returned !ok", mr)
	}
	if !h.b.UpdateNetmapDelta(muts) {
		h.t.Fatalf("UpdateNetmapDelta(%+v) returned false", muts)
	}
}

// readDirNames issues a real WebDAV PROPFIND against the local Taildrive
// root and returns the names of the directory entries the filesystem
// reports as available, sorted for stable comparison.
func (h *driveEndToEndHarness) readDirNames() []string {
	h.t.Helper()
	infos, err := h.client.ReadDir("/" + h.domain)
	if err != nil {
		h.t.Fatalf("ReadDir: %v", err)
	}
	var names []string
	for _, fi := range infos {
		names = append(names, fi.Name())
	}
	slices.Sort(names)
	return names
}

// waitForDir polls readDirNames until it matches want or the timeout
// elapses. We poll because the gen-bump → next-WebDAV-request rebuild has
// no happens-before synchronization with the caller of UpdateNetmapDelta;
// the rebuild happens lazily on the next inbound request.
func (h *driveEndToEndHarness) waitForDir(want []string) {
	h.t.Helper()
	slices.Sort(want)
	err := tstest.WaitFor(2*time.Second, func() error {
		got := h.readDirNames()
		if !slices.Equal(got, want) {
			return fmt.Errorf("readDirNames = %v, want %v", got, want)
		}
		return nil
	})
	if err != nil {
		h.t.Fatal(err)
	}
}

// TestDriveRemotesEndToEnd exercises the full pipeline from netmap mutation
// through driveGen invalidation, [driveRemoteSource.Remotes] re-evaluation,
// and compositedav child rebuild, validated by a real WebDAV PROPFIND each
// time.
//
// We cover the four ways a peer can enter or leave the drive-capable set:
//
//  1. Peer upsert (PeersChanged → NodeMutationUpsert): adds a brand-new
//     sharer peer.
//  2. Peer removal (PeersRemoved → NodeMutationRemove): removes an
//     existing sharer.
//  3. Packet-filter change (UpdatePacketFilter): flips an existing peer
//     in or out of the drive-capable set without any per-peer mutation.
//  4. Per-peer online toggle (OnlineChange → NodeMutationOnline): doesn't
//     change drive-capable membership but does change Available(), so the
//     PROPFIND listing must reflect it.
//
// Note: deltas are delivered via [LocalBackend.UpdateNetmapDelta] /
// [LocalBackend.UpdatePacketFilter] directly rather than through a real
// testcontrol stream. Those are the same entry points the controlclient
// calls into after parsing a MapResponse, so the LocalBackend-side
// semantics under test are identical; the wire-level netmap streaming
// itself is covered by [TestNetmapDeltaFastPath] in tstest/largetailnet.
func TestDriveRemotesEndToEnd(t *testing.T) {
	h := newDriveEndToEndHarness(t)

	peer2 := peerSpec{id: 2, name: "alpha", addr: netip.MustParseAddr("100.64.0.2"), online: true, driveCap: true, peerAPI: true}
	peer3 := peerSpec{id: 3, name: "bravo", addr: netip.MustParseAddr("100.64.0.3"), online: true, driveCap: false, peerAPI: true}

	// Initial state: peer2 has the sharer cap, peer3 does not. Only
	// peer2 should appear in the WebDAV listing.
	h.installNetMap([]peerSpec{peer2, peer3})
	h.waitForDir([]string{"alpha"})

	// 1) Upsert a new sharer peer (peer4) via PeersChanged, then refresh
	//    the packet filter so PeerHasCap returns true for it. PeerHasCap
	//    is driven by the filter, so adding the peer alone is not enough.
	peer4 := peerSpec{id: 4, name: "charlie", addr: netip.MustParseAddr("100.64.0.4"), online: true, driveCap: true, peerAPI: true}
	h.sendMapResponse(&tailcfg.MapResponse{
		PeersChanged: []*tailcfg.Node{peer4.node()},
	})
	if !h.b.UpdatePacketFilter(views.Slice[tailcfg.FilterRule]{}, h.filterMatchesFor([]peerSpec{peer2, peer3, peer4})) {
		t.Fatal("UpdatePacketFilter returned false")
	}
	h.waitForDir([]string{"alpha", "charlie"})

	// 2) Remove peer2 via PeersRemoved.
	h.sendMapResponse(&tailcfg.MapResponse{
		PeersRemoved: []tailcfg.NodeID{peer2.id},
	})
	if !h.b.UpdatePacketFilter(views.Slice[tailcfg.FilterRule]{}, h.filterMatchesFor([]peerSpec{peer3, peer4})) {
		t.Fatal("UpdatePacketFilter returned false")
	}
	h.waitForDir([]string{"charlie"})

	// 3) Flip peer3 into the drive-capable set by changing only the
	//    packet filter — no per-peer mutation. This exercises the
	//    UpdatePacketFilter bump path specifically.
	peer3.driveCap = true
	if !h.b.UpdatePacketFilter(views.Slice[tailcfg.FilterRule]{}, h.filterMatchesFor([]peerSpec{peer3, peer4})) {
		t.Fatal("UpdatePacketFilter returned false")
	}
	h.waitForDir([]string{"bravo", "charlie"})

	// 4) Toggle peer3 offline via OnlineChange. The peer is still in the
	//    drive-capable set so its name remains in the cached Remotes
	//    slice, but Available() returns false so dirfs filters it out of
	//    PROPFIND listings.
	h.sendMapResponse(&tailcfg.MapResponse{
		OnlineChange: map[tailcfg.NodeID]bool{peer3.id: false},
	})
	h.waitForDir([]string{"charlie"})

	// And back online.
	h.sendMapResponse(&tailcfg.MapResponse{
		OnlineChange: map[tailcfg.NodeID]bool{peer3.id: true},
	})
	h.waitForDir([]string{"bravo", "charlie"})
}
