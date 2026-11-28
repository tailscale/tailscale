// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netcheck

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/netmon"
	"tailscale.com/net/stun"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tstest"
	"tailscale.com/types/views"
)

func TestParseSTUNServer(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input string
		valid bool
	}{
		{"Hostname", "stun.example.com:3478", true},
		{"IPv4", "192.0.2.1:3478", true},
		{"IPv6", "[2001:db8::1]:3478", true},
		{"ScopedIPv6", "[fe80::1%eth0]:3478", true},
		{"MissingPort", "stun.example.com", false},
		{"MissingHost", ":3478", false},
		{"MissingPortValue", "stun.example.com:", false},
		{"ZeroPort", "stun.example.com:0", false},
		{"NegativePort", "stun.example.com:-1", false},
		{"LargePort", "stun.example.com:65536", false},
		{"NamedPort", "stun.example.com:stun", false},
		{"UnbracketedIPv6", "2001:db8::1:3478", false},
		{"URL", "stun://stun.example.com:3478", false},
		{"Whitespace", "stun.example.com :3478", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server, err := ParseSTUNServer(tt.input)
			if (err == nil) != tt.valid {
				t.Fatalf("ParseSTUNServer(%q) = %v, %v", tt.input, server, err)
			}
			if tt.valid && server.String() != tt.input {
				t.Errorf("String() = %q, want %q", server, tt.input)
			}
		})
	}
}

func TestReportGetGlobalAddrsRequiredSTUNEndpoints(t *testing.T) {
	v4 := netip.MustParseAddrPort("192.0.2.1:1234")
	extra4 := netip.MustParseAddrPort("192.0.2.2:2345")
	v6 := netip.MustParseAddrPort("[2001:db8::1]:1234")
	extra6 := netip.MustParseAddrPort("[2001:db8::2]:2345")
	r := &Report{
		GlobalV4:              v4,
		GlobalV6:              v6,
		GlobalV4Counters:      map[netip.AddrPort]int{v4: 1, extra4: 1},
		GlobalV6Counters:      map[netip.AddrPort]int{v6: 1, extra6: 1},
		RequiredSTUNEndpoints: []netip.AddrPort{v4, extra4, v6, extra6, extra4},
	}
	got4, got6 := r.GetGlobalAddrs()
	if want := []netip.AddrPort{v4, extra4}; !slices.Equal(got4, want) {
		t.Errorf("IPv4 = %v, want %v", got4, want)
	}
	if want := []netip.AddrPort{v6, extra6}; !slices.Equal(got6, want) {
		t.Errorf("IPv6 = %v, want %v", got6, want)
	}
}

func TestReportCloneRequiredSTUNEndpoints(t *testing.T) {
	addr := netip.MustParseAddrPort("192.0.2.1:1234")
	r := &Report{RequiredSTUNEndpoints: []netip.AddrPort{addr}}
	cloned := r.Clone()
	cloned.RequiredSTUNEndpoints[0] = netip.MustParseAddrPort("192.0.2.2:2345")
	if r.RequiredSTUNEndpoints[0] != addr {
		t.Error("Clone shares required endpoint storage")
	}
}

func TestClientGetReportRequiredSTUNProbes(t *testing.T) {
	tstest.ResourceCheck(t)
	for _, tt := range []struct {
		name        string
		incremental bool
		onlyTCP443  bool
		blackhole   bool
		duplicate   bool
	}{
		{name: "Initial"},
		{name: "Incremental", incremental: true},
		{name: "OnlyTCP443", onlyTCP443: true},
		{name: "UnreachableTarget", blackhole: true},
		{name: "DuplicateMappings", duplicate: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				stunEnabled := buildfeatures.HasNATTraversal && !tt.onlyTCP443
				c := newTestClient(t)
				c.SkipExternalNetwork = true
				var servers []STUNServer
				for _, s := range []string{"127.0.0.1:40001", "127.0.0.1:40002"} {
					server, err := ParseSTUNServer(s)
					if err != nil {
						t.Fatal(err)
					}
					servers = append(servers, server)
				}
				dm := stuntest.DERPMapOf("127.0.0.1:39001", "127.0.0.1:39002", "127.0.0.1:39003", "127.0.0.1:39004")
				if tt.incremental {
					c.lastFull = c.timeNow()
					c.last = newReport()
					c.last.PreferredDERP = 1
					for rid := range dm.Regions {
						c.last.RegionLatency[rid] = time.Millisecond
						c.last.RegionV4Latency[rid] = time.Millisecond
					}
				}
				var mu sync.Mutex
				counts := make(map[uint16]int)
				pending := make(map[netip.AddrPort][]byte)
				ordinary := netip.MustParseAddrPort("198.51.100.10:41641")
				want := []netip.AddrPort{
					netip.MustParseAddrPort("198.51.100.20:45678"),
					netip.MustParseAddrPort("198.51.100.30:56789"),
				}
				if tt.duplicate {
					want[1] = want[0]
				}
				c.SendPacket = func(pkt []byte, dst netip.AddrPort) (int, error) {
					tx, err := stun.ParseBindingRequest(pkt)
					if err != nil {
						t.Error(err)
						return 0, err
					}
					mu.Lock()
					counts[dst.Port()]++
					if dst.Port() >= 40001 {
						if !tt.blackhole || dst.Port() != 40002 {
							pending[dst] = stun.Response(tx, want[int(dst.Port())-40001])
						}
						mu.Unlock()
					} else {
						mu.Unlock()
						c.ReceiveSTUNPacket(stun.Response(tx, ordinary), dst)
					}
					return len(pkt), nil
				}
				type result struct {
					report *Report
					err    error
				}
				results := make(chan result, 1)
				go func() {
					r, err := c.GetReport(t.Context(), dm, &GetReportOpts{
						RequiredSTUNServers: views.SliceOf(servers),
						OnlyTCP443:          tt.onlyTCP443,
					})
					results <- result{r, err}
				}()
				synctest.Wait()
				if stunEnabled {
					select {
					case <-results:
						t.Fatal("report completed before required responses were released")
					default:
					}
				}
				// Release replies after ordinary probes have completed and required
				// probes are waiting. The virtual clock has not advanced to retries.
				for dst, pkt := range pending {
					c.ReceiveSTUNPacket(pkt, dst)
				}
				res := <-results
				if res.err != nil {
					t.Fatal(res.err)
				}
				r := res.report
				mu.Lock()
				defer mu.Unlock()
				if !stunEnabled {
					if len(counts) != 0 || len(r.RequiredSTUNEndpoints) != 0 {
						t.Fatal("UDP-disabled report sent STUN or retained a required mapping")
					}
					return
				}
				if tt.blackhole || tt.duplicate {
					want = want[:1]
				}
				got := slices.Clone(r.RequiredSTUNEndpoints)
				slices.SortFunc(got, netip.AddrPort.Compare)
				if !slices.Equal(got, want) {
					t.Errorf("required endpoints = %v, want %v", got, want)
				}
				v4, _ := r.GetGlobalAddrs()
				if !slices.Contains(v4, ordinary) {
					t.Errorf("ordinary mapping was lost: %v", v4)
				}
				for _, ep := range want {
					if !slices.Contains(v4, ep) {
						t.Errorf("required mapping %v was filtered out: %v", ep, v4)
					}
				}
				for _, server := range servers {
					if counts[server.port] == 0 {
						t.Errorf("required server %s was not probed", server)
					}
				}
				if _, ok := r.RegionLatency[0]; ok {
					t.Error("required probes added DERP latency measurements")
				}
			})
		})
	}

	t.Run("HTTPSFallback", func(t *testing.T) {
		if !buildfeatures.HasNATTraversal {
			t.Skip("requires NAT traversal")
		}
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()
		c := newTestClient(t)
		c.SkipExternalNetwork = true
		target, err := ParseSTUNServer("127.0.0.1:40001")
		if err != nil {
			t.Fatal(err)
		}
		mapping := netip.MustParseAddrPort("198.51.100.1:45678")
		c.SendPacket = func(pkt []byte, dst netip.AddrPort) (int, error) {
			if dst.Port() == target.port {
				tx, err := stun.ParseBindingRequest(pkt)
				if err != nil {
					t.Error(err)
					return 0, err
				}
				c.ReceiveSTUNPacket(stun.Response(tx, mapping), dst)
			}
			return len(pkt), nil
		}
		dm := stuntest.DERPMapOf("127.0.0.1:39001")
		node := dm.Regions[1].Nodes[0]
		node.STUNOnly = false
		node.DERPPort = server.Listener.Addr().(*net.TCPAddr).Port
		node.InsecureForTests = true
		r, err := c.GetReport(t.Context(), dm, &GetReportOpts{
			RequiredSTUNServers: views.SliceOf([]STUNServer{target}),
		})
		if err != nil {
			t.Fatal(err)
		}
		if !r.UDP || !r.IPv4 || !r.IPv4CanSend {
			t.Error("required response did not update final UDP availability")
		}
		if _, ok := r.RegionLatency[1]; !ok || r.PreferredDERP != 1 {
			t.Errorf("required probes suppressed DERP HTTPS fallback: %+v", r)
		}
		if !slices.Equal(r.RequiredSTUNEndpoints, []netip.AddrPort{mapping}) {
			t.Errorf("required mapping was lost during fallback: %v", r.RequiredSTUNEndpoints)
		}
	})
}

func TestReportStateRunRequiredSTUNProbe(t *testing.T) {
	tstest.ResourceCheck(t)
	for _, tt := range []struct {
		name  string
		host  string
		dst   string
		proto probeProto
		retry bool
	}{
		{"IPv4", "127.0.0.1:3478", "127.0.0.1:3478", probeIPv4, false},
		{"IPv6", "[::1]:3478", "[::1]:3478", probeIPv6, false},
		{"ScopedIPv6", "[fe80::1%eth0]:3478", "[fe80::1%eth0]:3478", probeIPv6, false},
		{"MappedIPv4", "[::ffff:127.0.0.1]:3478", "127.0.0.1:3478", probeIPv4, false},
		{"Hostname", "localhost:3478", "127.0.0.1:3478", probeIPv4, false},
		{"Retry", "127.0.0.1:3478", "127.0.0.1:3478", probeIPv4, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server, err := ParseSTUNServer(tt.host)
			if err != nil {
				t.Fatal(err)
			}
			c := newTestClient(t)
			rs := &reportState{c: c, report: newReport(), inFlight: make(map[stun.TxID]func(netip.AddrPort))}
			c.curState = rs
			mapping := netip.MustParseAddrPort("198.51.100.1:45678")
			if tt.proto == probeIPv6 {
				mapping = netip.MustParseAddrPort("[2001:db8::1]:45678")
			}
			attempts := 0
			c.SendPacket = func(pkt []byte, dst netip.AddrPort) (int, error) {
				if want := netip.MustParseAddrPort(tt.dst); dst != want {
					t.Errorf("STUN destination = %v, want %v", dst, want)
				}
				attempts++
				if tt.retry && attempts == 1 {
					return len(pkt), nil
				}
				tx, err := stun.ParseBindingRequest(pkt)
				if err != nil {
					t.Fatal(err)
				}
				c.ReceiveSTUNPacket(stun.Response(stun.NewTxID(), mapping), dst)
				c.ReceiveSTUNPacket(stun.Response(tx, mapping), dst)
				c.ReceiveSTUNPacket(stun.Response(tx, mapping), dst)
				return len(pkt), nil
			}
			ctx, cancel := context.WithTimeout(t.Context(), stunProbeTimeout)
			defer cancel()
			rs.runRequiredSTUNProbe(ctx, server, tt.proto)
			if !slices.Equal(rs.report.RequiredSTUNEndpoints, []netip.AddrPort{mapping}) {
				t.Errorf("required endpoints = %v", rs.report.RequiredSTUNEndpoints)
			}
			if rs.report.UDP || rs.report.IPv4 || rs.report.IPv6 {
				t.Error("required response changed ordinary probe availability before report completion")
			}
			if len(rs.inFlight) != 0 {
				t.Error("probe leaked transactions")
			}
		})
	}

	t.Run("Failures", func(t *testing.T) {
		for _, tt := range []struct {
			name        string
			noSender    bool
			canceled    bool
			writeErr    error
			shortWrite  bool
			mapping     string
			attempts    int
			wantCanSend bool
		}{
			{name: "NoSender", noSender: true},
			{name: "Canceled", canceled: true},
			{name: "WriteError", writeErr: errors.New("send failed"), attempts: 3},
			{name: "ShortWrite", shortWrite: true, attempts: 3},
			{name: "Timeout", attempts: 3, wantCanSend: true},
			{name: "ZeroPort", mapping: "198.51.100.1:0", attempts: 3, wantCanSend: true},
			{name: "UnspecifiedAddress", mapping: "0.0.0.0:45678", attempts: 3, wantCanSend: true},
			{name: "MulticastAddress", mapping: "224.0.0.1:45678", attempts: 3, wantCanSend: true},
		} {
			t.Run(tt.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					c := newTestClient(t)
					rs := &reportState{c: c, report: newReport(), inFlight: make(map[stun.TxID]func(netip.AddrPort))}
					c.curState = rs
					attempts := 0
					c.SendPacket = func(pkt []byte, dst netip.AddrPort) (int, error) {
						attempts++
						if tt.mapping != "" {
							tx, err := stun.ParseBindingRequest(pkt)
							if err != nil {
								t.Fatal(err)
							}
							c.ReceiveSTUNPacket(stun.Response(tx, netip.MustParseAddrPort(tt.mapping)), dst)
						}
						if tt.shortWrite {
							return len(pkt) - 1, nil
						}
						return len(pkt), tt.writeErr
					}
					if tt.noSender {
						c.SendPacket = nil
					}
					ctx, cancel := context.WithTimeout(t.Context(), stunProbeTimeout)
					defer cancel()
					if tt.canceled {
						cancel()
					}
					server, err := ParseSTUNServer("127.0.0.1:3478")
					if err != nil {
						t.Fatal(err)
					}
					rs.runRequiredSTUNProbe(ctx, server, probeIPv4)
					if attempts != tt.attempts {
						t.Errorf("STUN sends = %v, want %v", attempts, tt.attempts)
					}
					if len(rs.inFlight) != 0 || len(rs.report.RequiredSTUNEndpoints) != 0 {
						t.Error("failed probe retained a transaction or mapping")
					}
					if rs.report.IPv4CanSend != tt.wantCanSend || rs.report.UDP {
						t.Errorf("UDP availability = %v, %v, want %v, false", rs.report.IPv4CanSend, rs.report.UDP, tt.wantCanSend)
					}
				})
			})
		}
	})

	t.Run("Cancellation", func(t *testing.T) {
		c := newTestClient(t)
		rs := &reportState{c: c, report: newReport(), inFlight: make(map[stun.TxID]func(netip.AddrPort))}
		c.curState = rs
		ctx, cancel := context.WithTimeout(t.Context(), stunProbeTimeout)
		defer cancel()
		var tx stun.TxID
		c.SendPacket = func(pkt []byte, _ netip.AddrPort) (int, error) {
			tx, _ = stun.ParseBindingRequest(pkt)
			cancel()
			return len(pkt), nil
		}
		server, err := ParseSTUNServer("127.0.0.1:3478")
		if err != nil {
			t.Fatal(err)
		}
		rs.runRequiredSTUNProbe(ctx, server, probeIPv4)
		if tx == (stun.TxID{}) {
			t.Fatal("probe did not send a STUN request before cancellation")
		}
		c.ReceiveSTUNPacket(stun.Response(tx, netip.MustParseAddrPort("198.51.100.1:45678")), netip.MustParseAddrPort(server.String()))
		if len(rs.report.RequiredSTUNEndpoints) != 0 || len(rs.inFlight) != 0 {
			t.Error("canceled probe accepted a late response or leaked a transaction")
		}
	})
}

func TestReportStateStartRequiredSTUNProbes(t *testing.T) {
	tstest.ResourceCheck(t)
	t.Run("DNSDeadline", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c := newTestClient(t)
			c.UseDNSCache = true
			c.resolver = &dnscache.Resolver{LookupIPForTest: func(ctx context.Context, host string) ([]netip.Addr, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}}
			c.SendPacket = func([]byte, netip.AddrPort) (int, error) {
				t.Error("unresolved target sent a packet")
				return 0, nil
			}
			server, err := ParseSTUNServer("stun.test:3478")
			if err != nil {
				t.Fatal(err)
			}
			rs := &reportState{c: c, opts: &GetReportOpts{RequiredSTUNServers: views.SliceOf([]STUNServer{server})}}
			start := time.Now()
			<-rs.startRequiredSTUNProbes(t.Context(), &netmon.State{HaveV4: true})
			synctest.Wait()
			if elapsed := time.Since(start); elapsed != stunProbeTimeout {
				t.Errorf("DNS timeout = %v, want %v", elapsed, stunProbeTimeout)
			}
		})
	})

	t.Run("NoAddressFamily", func(t *testing.T) {
		c := newTestClient(t)
		server, err := ParseSTUNServer("127.0.0.1:3478")
		if err != nil {
			t.Fatal(err)
		}
		rs := &reportState{c: c, opts: &GetReportOpts{RequiredSTUNServers: views.SliceOf([]STUNServer{server})}}
		select {
		case <-t.Context().Done():
			t.Fatal("test canceled")
		case <-rs.startRequiredSTUNProbes(t.Context(), &netmon.State{}):
		case <-time.After(time.Second):
			t.Fatal("probe with no available address family did not complete")
		}
	})

	t.Run("BlockedSender", func(t *testing.T) {
		c := newTestClient(t)
		server, err := ParseSTUNServer("127.0.0.1:3478")
		if err != nil {
			t.Fatal(err)
		}
		rs := &reportState{
			c:        c,
			opts:     &GetReportOpts{RequiredSTUNServers: views.SliceOf([]STUNServer{server})},
			report:   newReport(),
			inFlight: make(map[stun.TxID]func(netip.AddrPort)),
		}
		c.curState = rs
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		entered := make(chan stun.TxID, 1)
		release := make(chan struct{})
		returned := make(chan struct{})
		c.SendPacket = func(pkt []byte, _ netip.AddrPort) (int, error) {
			defer close(returned)
			tx, _ := stun.ParseBindingRequest(pkt)
			entered <- tx
			<-release
			return len(pkt), nil
		}
		t.Cleanup(func() {
			close(release)
			select {
			case <-returned:
			case <-time.After(time.Second):
				t.Error("sender did not return after release")
			}
		})
		done := rs.startRequiredSTUNProbes(ctx, &netmon.State{HaveV4: true})
		var tx stun.TxID
		select {
		case tx = <-entered:
		case <-time.After(time.Second):
			t.Fatal("probe did not enter the sender")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("blocked sender prevented probe cancellation")
		}
		c.ReceiveSTUNPacket(stun.Response(tx, netip.MustParseAddrPort("198.51.100.1:45678")), netip.MustParseAddrPort(server.String()))
		rs.mu.Lock()
		defer rs.mu.Unlock()
		if len(rs.report.RequiredSTUNEndpoints) != 0 {
			t.Error("expired probe accepted a response while its sender was blocked")
		}
	})
}
