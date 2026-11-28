// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/net/stun"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
	"tailscale.com/util/eventbus/eventbustest"
)

func TestConnSetRequiredSTUNServers(t *testing.T) {
	server, err := netcheck.ParseSTUNServer("127.0.0.1:3478")
	if err != nil {
		t.Fatal(err)
	}
	c := &Conn{endpointsUpdateActive: true}
	for _, tt := range []struct {
		name    string
		servers []netcheck.STUNServer
		changed bool
	}{
		{name: "Unset"},
		{name: "Add", servers: []netcheck.STUNServer{server}, changed: true},
		{name: "Unchanged", servers: []netcheck.STUNServer{server}},
		{name: "Clear", changed: true},
		{name: "Empty", servers: []netcheck.STUNServer{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			servers := views.SliceOf(tt.servers)
			c.SetRequiredSTUNServers(servers)
			c.mu.Lock()
			defer c.mu.Unlock()
			if !views.SliceEqual(c.requiredSTUNServers, servers) {
				t.Errorf("required STUN servers were not updated")
			}
			if got := c.wantEndpointsUpdate != ""; got != tt.changed {
				t.Errorf("endpoint update queued = %v, want %v", got, tt.changed)
			}
			c.wantEndpointsUpdate = ""
		})
	}
}

func TestConnShouldDoPeriodicReSTUNLocked(t *testing.T) {
	server, err := netcheck.ParseSTUNServer("127.0.0.1:3478")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name       string
		required   bool
		peers      bool
		idle       bool
		stopped    bool
		down       bool
		homeless   bool
		onlyTCP443 bool
		want       bool
	}{
		{name: "DefaultWithoutPeers"},
		{name: "DefaultWithPeers", peers: true, want: true},
		{name: "DefaultIdleWithPeers", peers: true, idle: true},
		{name: "RequiredIdleWithoutPeers", required: true, idle: true, want: hasUDPTransport},
		{name: "RequiredWithPeers", required: true, peers: true, want: true},
		{name: "RequiredIdleWithPeers", required: true, peers: true, idle: true, want: hasUDPTransport},
		{name: "Stopped", required: true, stopped: true},
		{name: "NetworkDown", required: true, down: true},
		{name: "Homeless", required: true, homeless: true},
		{name: "OnlyTCP443", required: true, onlyTCP443: true},
		{name: "OnlyTCP443WithPeers", required: true, peers: true, onlyTCP443: true, want: true},
		{name: "OnlyTCP443IdleWithPeers", required: true, peers: true, idle: true, onlyTCP443: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &Conn{
				privateKey:                key.NewNode(),
				homeless:                  tt.homeless,
				checkNetworkUpDuringTests: true,
				idleFunc: func() time.Duration {
					if tt.idle {
						return time.Hour
					}
					return 0
				},
			}
			if tt.peers {
				c.peersByID = map[tailcfg.NodeID]tailcfg.NodeView{1: {}}
			}
			c.networkUp.Store(!tt.down)
			c.onlyTCP443.Store(tt.onlyTCP443)
			if tt.stopped {
				c.privateKey = key.NodePrivate{}
			}
			if tt.required {
				c.requiredSTUNServers = views.SliceOf([]netcheck.STUNServer{server})
			}
			c.mu.Lock()
			got := c.shouldDoPeriodicReSTUNLocked()
			c.mu.Unlock()
			if want := tt.want && buildfeatures.HasNATTraversal; got != want {
				t.Errorf("shouldDoPeriodicReSTUNLocked() = %v, want %v", got, want)
			}
		})
	}
}

func TestConnUpdateNetInfoRequiredSTUNServers(t *testing.T) {
	tstest.ResourceCheck(t)
	for _, tt := range []struct {
		name       string
		onlyTCP443 bool
	}{
		{name: "Default"},
		{name: "OnlyTCP443", onlyTCP443: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				mon := netmon.NewStatic()
				if !mon.InterfaceState().HaveV4 {
					t.Skip("requires an IPv4 interface")
				}
				c := newConn(t.Logf)
				c.health = health.NewTracker(eventbustest.NewBus(t))
				c.derpMap = &tailcfg.DERPMap{}
				c.onlyTCP443.Store(tt.onlyTCP443)
				server, err := netcheck.ParseSTUNServer("127.0.0.1:3478")
				if err != nil {
					t.Fatal(err)
				}
				mapping := netip.MustParseAddrPort("198.51.100.1:45678")
				var sends atomic.Int32
				c.netChecker = &netcheck.Client{
					NetMon:              mon,
					Logf:                t.Logf,
					SkipExternalNetwork: true,
				}
				c.netChecker.SendPacket = func(pkt []byte, dst netip.AddrPort) (int, error) {
					sends.Add(1)
					if !hasUDPTransport {
						return 0, errors.ErrUnsupported
					}
					tx, err := stun.ParseBindingRequest(pkt)
					if err != nil {
						t.Error(err)
						return 0, err
					}
					c.netChecker.ReceiveSTUNPacket(stun.Response(tx, mapping), dst)
					return len(pkt), nil
				}
				start := time.Now()
				if _, err := c.updateNetInfo(t.Context()); err != nil {
					t.Fatal(err)
				}
				baselineDelay := time.Since(start)
				c.requiredSTUNServers = views.SliceOf([]netcheck.STUNServer{server})
				start = time.Now()
				r, err := c.updateNetInfo(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				enabled := hasUDPTransport && buildfeatures.HasNATTraversal && !tt.onlyTCP443
				var want []netip.AddrPort
				if enabled {
					want = []netip.AddrPort{mapping}
				}
				if !slices.Equal(r.RequiredSTUNEndpoints, want) {
					t.Errorf("required mappings = %v, want %v", r.RequiredSTUNEndpoints, want)
				}
				if got := sends.Load(); enabled && got == 0 || !enabled && got != 0 {
					t.Errorf("STUN sends = %v, enabled = %v", got, enabled)
				}
				if elapsed := time.Since(start); elapsed != baselineDelay {
					t.Errorf("report delay = %v, want baseline %v", elapsed, baselineDelay)
				}
			})
		})
	}
}

func TestConnRequiredSTUNProbes(t *testing.T) {
	if !buildfeatures.HasNATTraversal || !hasUDPTransport {
		t.Skip("requires NAT traversal and UDP transport")
	}
	tstest.ResourceCheck(t)

	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var mapping, source syncs.MutexValue[netip.AddrPort]
	publicIP := netip.MustParseAddr("198.51.100.20")
	mapping.Store(netip.AddrPortFrom(publicIP, 45677))
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, src, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			tx, err := stun.ParseBindingRequest(buf[:n])
			if err != nil {
				t.Error(err)
				return
			}
			source.Store(src)
			if _, err := pc.WriteToUDPAddrPort(stun.Response(tx, mapping.Load()), src); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	t.Cleanup(func() {
		pc.Close()
		<-done
	})
	server, err := netcheck.ParseSTUNServer(pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	derpMap, cleanup := runDERPAndStun(t, t.Logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1))
	defer cleanup()
	m1 := newMagicStack(t, t.Logf, localhostListener{}, derpMap)
	defer m1.Close()
	m1.conn.SetRequiredSTUNServers(views.SliceOf([]netcheck.STUNServer{server}))
	m2 := newMagicStack(t, t.Logf, localhostListener{}, derpMap)
	defer m2.Close()
	cleanupMesh := meshStacks(t.Logf, nil, m1, m2)
	defer cleanupMesh()
	cleanupPinger := newPinger(t, t.Logf, m1, m2)
	defer cleanupPinger()
	updateMapping := func(t *testing.T, port uint16) {
		t.Helper()
		want := netip.AddrPortFrom(publicIP, port)
		mapping.Store(want)
		m1.conn.ReSTUN("required-stun-test")
		if err := tstest.WaitFor(5*time.Second, func() error {
			m1.conn.mu.Lock()
			found := slices.ContainsFunc(m1.conn.lastEndpoints, func(ep tailcfg.Endpoint) bool {
				return ep.Addr == want && ep.Type == tailcfg.EndpointSTUN
			})
			m1.conn.mu.Unlock()
			if !found {
				return fmt.Errorf("mapping %v is not advertised", want)
			}
			if got, wantPort := source.Load().Port(), m1.conn.LocalPort(); got != wantPort {
				return fmt.Errorf("STUN source port = %v, live magicsock port = %v", got, wantPort)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("MappingUpdates", func(t *testing.T) {
		for i := range 10 {
			updateMapping(t, uint16(45678+i))
		}
	})

	t.Run("ConcurrentRebind", func(t *testing.T) {
		var rebinds sync.WaitGroup
		rebinds.Go(func() {
			for range 10 {
				m1.conn.SetRequiredSTUNServers(views.Slice[netcheck.STUNServer]{})
				m1.conn.SetStaticEndpoints(views.SliceOf([]netip.AddrPort{netip.MustParseAddrPort("198.51.100.40:41641")}))
				m1.conn.Rebind()
				m1.conn.SetStaticEndpoints(views.Slice[netip.AddrPort]{})
				m1.conn.SetRequiredSTUNServers(views.SliceOf([]netcheck.STUNServer{server}))
				time.Sleep(time.Millisecond)
			}
		})
		defer rebinds.Wait()
		for i := range 10 {
			if i%2 == 0 {
				m1.conn.Rebind()
			}
			updateMapping(t, uint16(45688+i))
		}
		mustDirect(t, t.Logf, m1, m2)
		mustDirect(t, t.Logf, m2, m1)
	})

	t.Run("Expiry", func(t *testing.T) {
		// Advance the tracker's existing time input, without depending on its
		// heap layout or waiting for the cache lifetime to elapse.
		m1.conn.endpointTracker.update(time.Now().Add(endpointTrackerLifetime+time.Second), nil)
		m1.conn.ReSTUN("required-stun-expiry-test")
		if err := tstest.WaitFor(5*time.Second, func() error {
			m1.conn.mu.Lock()
			defer m1.conn.mu.Unlock()
			var required []netip.AddrPort
			for _, ep := range m1.conn.lastEndpoints {
				if ep.Addr.Addr() == publicIP {
					required = append(required, ep.Addr)
				}
			}
			if !slices.Equal(required, []netip.AddrPort{mapping.Load()}) {
				return fmt.Errorf("expired required mappings are still advertised: %v", required)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestConnSetPrivateKeyStopsQueuedRequiredSTUNProbes(t *testing.T) {
	if !buildfeatures.HasNATTraversal || !hasUDPTransport {
		t.Skip("requires NAT traversal and UDP transport")
	}
	tstest.ResourceCheck(t)
	dm, closeDERP := runDERPAndStun(t, t.Logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1))
	defer closeDERP()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	mapping := netip.MustParseAddrPort("198.51.100.71:45678")
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		n, src, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		tx, err := stun.ParseBindingRequest(buf[:n])
		if err != nil {
			t.Error(err)
			return
		}
		close(started)
		<-release
		if _, err := pc.WriteToUDPAddrPort(stun.Response(tx, mapping), src); err != nil {
			t.Logf("STUN response: %v", err)
		}
	}()
	t.Cleanup(func() {
		unblock()
		pc.Close()
		<-done
	})
	a, err := netcheck.ParseSTUNServer(pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	stunAddr := netip.AddrPortFrom(
		netip.MustParseAddr("127.0.0.1"),
		uint16(dm.Regions[1].Nodes[0].STUNPort),
	)
	b, err := netcheck.ParseSTUNServer(stunAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	m := newMagicStack(t, t.Logf, localhostListener{}, dm)
	defer m.Close()
	m.conn.SetRequiredSTUNServers(views.SliceOf([]netcheck.STUNServer{a}))
	select {
	case <-t.Context().Done():
		t.Fatal("test canceled")
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("old probe did not start")
	}
	m.conn.SetRequiredSTUNServers(views.SliceOf([]netcheck.STUNServer{b}))
	m.conn.mu.Lock()
	queued := m.conn.wantEndpointsUpdate != ""
	m.conn.mu.Unlock()
	if !queued {
		t.Fatal("replacement probe was not queued")
	}
	if err := m.conn.SetPrivateKey(key.NodePrivate{}); err != nil {
		t.Fatal(err)
	}
	unblock()
	if err := tstest.WaitFor(5*time.Second, func() error {
		m.conn.mu.Lock()
		defer m.conn.mu.Unlock()
		if m.conn.endpointsUpdateActive {
			return fmt.Errorf("waiting for in-flight discovery to finish")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if r := m.conn.GetLastNetcheckReport(t.Context()); r == nil || !slices.Equal(r.RequiredSTUNEndpoints, []netip.AddrPort{mapping}) {
		t.Fatalf("queued discovery ran after stop: last report = %v", r)
	}
	if err := m.conn.SetPrivateKey(m.privateKey); err != nil {
		t.Fatal(err)
	}
	if err := tstest.WaitFor(5*time.Second, func() error {
		r := m.conn.GetLastNetcheckReport(t.Context())
		want := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), m.conn.LocalPort())
		if r == nil || !slices.Equal(r.RequiredSTUNEndpoints, []netip.AddrPort{want}) {
			return fmt.Errorf("resumed discovery did not use the queued target")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
