// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netcheck

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/net/netmon"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/nettest"
)

func newTestClient(t testing.TB) *Client {
	c := &Client{
		NetMon: netmon.NewStatic(),
		Logf:   t.Logf,
	}
	return c
}

func TestBasic(t *testing.T) {
	stunAddr, cleanup := stuntest.Serve(t)
	defer cleanup()

	c := newTestClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	if err := c.Standalone(ctx, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}

	r, err := c.GetReport(ctx, stuntest.DERPMapOf(stunAddr.String()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !r.UDP {
		t.Error("want UDP")
	}
	if len(r.RegionLatency) != 1 {
		t.Errorf("expected 1 key in DERPLatency; got %+v", r.RegionLatency)
	}
	if _, ok := r.RegionLatency[1]; !ok {
		t.Errorf("expected key 1 in DERPLatency; got %+v", r.RegionLatency)
	}
	if !r.GlobalV4.IsValid() {
		t.Error("expected GlobalV4 set")
	}
	if r.PreferredDERP != 1 {
		t.Errorf("PreferredDERP = %v; want 1", r.PreferredDERP)
	}
	v4Addrs, _ := r.GetGlobalAddrs()
	if len(v4Addrs) != 1 {
		t.Error("expected one global IPv4 address")
	}
	if got, want := v4Addrs[0], r.GlobalV4; got != want {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestMultiGlobalAddressMapping(t *testing.T) {
	c := &Client{
		Logf: t.Logf,
	}

	rs := &reportState{
		c:      c,
		start:  time.Now(),
		report: newReport(),
	}
	derpNode := &tailcfg.DERPNode{}
	port1 := netip.MustParseAddrPort("127.0.0.1:1234")
	port2 := netip.MustParseAddrPort("127.0.0.1:2345")
	port3 := netip.MustParseAddrPort("127.0.0.1:3456")
	// First report for port1
	rs.addNodeLatency(derpNode, port1, 10*time.Millisecond)
	// Singular report for port2
	rs.addNodeLatency(derpNode, port2, 11*time.Millisecond)
	// Duplicate reports for port3
	rs.addNodeLatency(derpNode, port3, 12*time.Millisecond)
	rs.addNodeLatency(derpNode, port3, 13*time.Millisecond)

	r := rs.report
	v4Addrs, _ := r.GetGlobalAddrs()
	wantV4Addrs := []netip.AddrPort{port1, port3}
	if !slices.Equal(v4Addrs, wantV4Addrs) {
		t.Errorf("got global addresses: %v, want %v", v4Addrs, wantV4Addrs)
	}
}

func TestWorksWhenUDPBlocked(t *testing.T) {
	blackhole, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to open blackhole STUN listener: %v", err)
	}
	defer blackhole.Close()

	stunAddr := blackhole.LocalAddr().String()

	dm := stuntest.DERPMapOf(stunAddr)
	dm.Regions[1].Nodes[0].STUNOnly = true

	c := newTestClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	r, err := c.GetReport(ctx, dm, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.UPnP = ""
	r.PMP = ""
	r.PCP = ""

	want := newReport()

	// The IPv4CanSend flag gets set differently across platforms.
	// On Windows this test detects false, while on Linux detects true.
	// That's not relevant to this test, so just accept what we're
	// given.
	want.IPv4CanSend = r.IPv4CanSend
	// OS IPv6 test is irrelevant here, accept whatever the current
	// machine has.
	want.OSHasIPv6 = r.OSHasIPv6
	// Captive portal test is irrelevant; accept what the current report
	// has.
	want.CaptivePortal = r.CaptivePortal

	if !reflect.DeepEqual(r, want) {
		t.Errorf("mismatch\n got: %+v\nwant: %+v\n", r, want)
	}
}

func TestAddReportHistoryAndSetPreferredDERP(t *testing.T) {
	// report returns a *Report from (DERP host, time.Duration)+ pairs.
	report := func(a ...any) *Report {
		r := &Report{RegionLatency: map[int]time.Duration{}}
		for i := 0; i < len(a); i += 2 {
			s := a[i].(string)
			if !strings.HasPrefix(s, "d") {
				t.Fatalf("invalid derp server key %q", s)
			}
			regionID, err := strconv.Atoi(s[1:])
			if err != nil {
				t.Fatalf("invalid derp server key %q", s)
			}

			switch v := a[i+1].(type) {
			case time.Duration:
				r.RegionLatency[regionID] = v
			case int:
				r.RegionLatency[regionID] = time.Second * time.Duration(v)
			default:
				panic(fmt.Sprintf("unexpected type %T", v))
			}
		}
		return r
	}
	mkLDAFunc := func(mm map[int]time.Time) func(int) time.Time {
		return func(region int) time.Time {
			return mm[region]
		}
	}
	type step struct {
		after time.Duration
		r     *Report
	}
	startTime := time.Unix(123, 0)
	tests := []struct {
		name        string
		steps       []step
		homeParams  *tailcfg.DERPHomeParams
		opts        *GetReportOpts
		wantDERP    int // want PreferredDERP on final step
		wantPrevLen int // wanted len(c.prev)
	}{
		{
			name: "first_reading",
			steps: []step{
				{0, report("d1", 2, "d2", 3)},
			},
			wantPrevLen: 1,
			wantDERP:    1,
		},
		{
			name: "with_two",
			steps: []step{
				{0, report("d1", 2, "d2", 3)},
				{1 * time.Second, report("d1", 4, "d2", 3)},
			},
			wantPrevLen: 2,
			wantDERP:    1, // t0's d1 of 2 is still best
		},
		{
			name: "but_now_d1_gone",
			steps: []step{
				{0, report("d1", 2, "d2", 3)},
				{1 * time.Second, report("d1", 4, "d2", 3)},
				{2 * time.Second, report("d2", 3)},
			},
			wantPrevLen: 3,
			wantDERP:    2, // only option
		},
		{
			name: "d1_is_back",
			steps: []step{
				{0, report("d1", 2, "d2", 3)},
				{1 * time.Second, report("d1", 4, "d2", 3)},
				{2 * time.Second, report("d2", 3)},
				{3 * time.Second, report("d1", 4, "d2", 3)}, // same as 2 seconds ago
			},
			wantPrevLen: 4,
			wantDERP:    1, // t0's d1 of 2 is still best
		},
		{
			name: "things_clean_up",
			steps: []step{
				{0, report("d1", 1, "d2", 2)},
				{1 * time.Second, report("d1", 1, "d2", 2)},
				{2 * time.Second, report("d1", 1, "d2", 2)},
				{3 * time.Second, report("d1", 1, "d2", 2)},
				{10 * time.Minute, report("d3", 3)},
			},
			wantPrevLen: 1, // t=[0123]s all gone. (too old, older than 10 min)
			wantDERP:    3, // only option
		},
		{
			name: "preferred_derp_hysteresis_no_switch",
			steps: []step{
				{0 * time.Second, report("d1", 4, "d2", 5)},
				{1 * time.Second, report("d1", 4, "d2", 3)},
			},
			wantPrevLen: 2,
			wantDERP:    1, // 2 didn't get fast enough
		},
		{
			name: "preferred_derp_hysteresis_no_switch_absolute",
			steps: []step{
				{0 * time.Second, report("d1", 4*time.Millisecond, "d2", 5*time.Millisecond)},
				{1 * time.Second, report("d1", 4*time.Millisecond, "d2", 1*time.Millisecond)},
			},
			wantPrevLen: 2,
			wantDERP:    1, // 2 is 50%+ faster, but the absolute diff is <10ms
		},
		{
			name: "preferred_derp_hysteresis_do_switch",
			steps: []step{
				{0 * time.Second, report("d1", 4, "d2", 5)},
				{1 * time.Second, report("d1", 4, "d2", 1)},
			},
			wantPrevLen: 2,
			wantDERP:    2, // 2 got fast enough
		},
		{
			name: "derp_home_params",
			homeParams: &tailcfg.DERPHomeParams{
				RegionScore: map[int]float64{
					1: 2.0 / 3, // 66%
				},
			},
			steps: []step{
				// We only use a single step here to avoid
				// conflating DERP selection as a result of
				// weight hints with the "stickiness" check
				// that tries to not change the home DERP
				// between steps.
				{1 * time.Second, report("d1", 10, "d2", 8)},
			},
			wantPrevLen: 1,
			wantDERP:    1, // 2 was faster, but not by 50%+
		},
		{
			name: "derp_home_params_high_latency",
			homeParams: &tailcfg.DERPHomeParams{
				RegionScore: map[int]float64{
					1: 2.0 / 3, // 66%
				},
			},
			steps: []step{
				// See derp_home_params for why this is a single step.
				{1 * time.Second, report("d1", 100, "d2", 10)},
			},
			wantPrevLen: 1,
			wantDERP:    2, // 2 was faster by more than 50%
		},
		{
			name: "derp_home_params_invalid",
			homeParams: &tailcfg.DERPHomeParams{
				RegionScore: map[int]float64{
					1: 0.0,
					2: -1.0,
				},
			},
			steps: []step{
				{1 * time.Second, report("d1", 4, "d2", 5)},
			},
			wantPrevLen: 1,
			wantDERP:    1,
		},
		{
			name: "saw_derp_traffic",
			steps: []step{
				{0, report("d1", 2, "d2", 3)},               // (1) initially pick d1
				{2 * time.Second, report("d1", 4, "d2", 3)}, // (2) still d1
				{2 * time.Second, report("d2", 3)},          // (3) d1 gone, but have traffic
			},
			opts: &GetReportOpts{
				GetLastDERPActivity: mkLDAFunc(map[int]time.Time{
					1: startTime.Add(2*time.Second + PreferredDERPFrameTime/2), // within active window of step (3)
				}),
			},
			wantPrevLen: 3,
			wantDERP:    1, // still on 1 since we got traffic from it
		},
		{
			name: "saw_derp_traffic_history",
			steps: []step{
				{0, report("d1", 2, "d2", 3)},               // (1) initially pick d1
				{2 * time.Second, report("d1", 4, "d2", 3)}, // (2) still d1
				{2 * time.Second, report("d2", 3)},          // (3) d1 gone, but have traffic
			},
			opts: &GetReportOpts{
				GetLastDERPActivity: mkLDAFunc(map[int]time.Time{
					1: startTime.Add(4*time.Second - PreferredDERPFrameTime - 1), // not within active window of (3)
				}),
			},
			wantPrevLen: 3,
			wantDERP:    2, // moved to d2 since d1 is gone
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeTime := startTime
			c := &Client{
				TimeNow: func() time.Time { return fakeTime },
			}
			dm := &tailcfg.DERPMap{HomeParams: tt.homeParams}
			rs := &reportState{
				c:     c,
				start: fakeTime,
				opts:  tt.opts,
			}
			for _, s := range tt.steps {
				fakeTime = fakeTime.Add(s.after)
				rs.start = fakeTime.Add(-100 * time.Millisecond)
				c.addReportHistoryAndSetPreferredDERP(rs, s.r, dm.View())
			}
			lastReport := tt.steps[len(tt.steps)-1].r
			if got, want := len(c.prev), tt.wantPrevLen; got != want {
				t.Errorf("len(prev) = %v; want %v", got, want)
			}
			if got, want := lastReport.PreferredDERP, tt.wantDERP; got != want {
				t.Errorf("PreferredDERP = %v; want %v", got, want)
			}
		})
	}
}

func TestMakeProbePlan(t *testing.T) {
	// basicMap has 5 regions. each region has a number of nodes
	// equal to the region number (1 has 1a, 2 has 2a and 2b, etc.)
	basicMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{},
	}
	for rid := 1; rid <= 5; rid++ {
		var nodes []*tailcfg.DERPNode
		for nid := 0; nid < rid; nid++ {
			nodes = append(nodes, &tailcfg.DERPNode{
				Name:     fmt.Sprintf("%d%c", rid, 'a'+rune(nid)),
				RegionID: rid,
				HostName: fmt.Sprintf("derp%d-%d", rid, nid),
				IPv4:     fmt.Sprintf("%d.0.0.%d", rid, nid),
				IPv6:     fmt.Sprintf("%d::%d", rid, nid),
			})
		}
		basicMap.Regions[rid] = &tailcfg.DERPRegion{
			RegionID: rid,
			Nodes:    nodes,
		}
	}

	const ms = time.Millisecond
	p := func(name string, c rune, d ...time.Duration) probe {
		var proto probeProto
		switch c {
		case 4:
			proto = probeIPv4
		case 6:
			proto = probeIPv6
		case 'h':
			proto = probeHTTPS
		}
		pr := probe{node: name, proto: proto}
		if len(d) == 1 {
			pr.delay = d[0]
		} else if len(d) > 1 {
			panic("too many args")
		}
		return pr
	}
	tests := []struct {
		name    string
		dm      *tailcfg.DERPMap
		have6if bool
		no4     bool // no IPv4
		last    *Report
		want    probePlan
	}{
		{
			name:    "initial_v6",
			dm:      basicMap,
			have6if: true,
			last:    nil, // initial
			want: probePlan{
				"region-1-v4": []probe{p("1a", 4), p("1a", 4, 100*ms), p("1a", 4, 200*ms)}, // all a
				"region-1-v6": []probe{p("1a", 6), p("1a", 6, 100*ms), p("1a", 6, 200*ms)},
				"region-2-v4": []probe{p("2a", 4), p("2b", 4, 100*ms), p("2a", 4, 200*ms)}, // a -> b -> a
				"region-2-v6": []probe{p("2a", 6), p("2b", 6, 100*ms), p("2a", 6, 200*ms)},
				"region-3-v4": []probe{p("3a", 4), p("3b", 4, 100*ms), p("3c", 4, 200*ms)}, // a -> b -> c
				"region-3-v6": []probe{p("3a", 6), p("3b", 6, 100*ms), p("3c", 6, 200*ms)},
				"region-4-v4": []probe{p("4a", 4), p("4b", 4, 100*ms), p("4c", 4, 200*ms)},
				"region-4-v6": []probe{p("4a", 6), p("4b", 6, 100*ms), p("4c", 6, 200*ms)},
				"region-5-v4": []probe{p("5a", 4), p("5b", 4, 100*ms), p("5c", 4, 200*ms)},
				"region-5-v6": []probe{p("5a", 6), p("5b", 6, 100*ms), p("5c", 6, 200*ms)},
			},
		},
		{
			name:    "initial_no_v6",
			dm:      basicMap,
			have6if: false,
			last:    nil, // initial
			want: probePlan{
				"region-1-v4": []probe{p("1a", 4), p("1a", 4, 100*ms), p("1a", 4, 200*ms)}, // all a
				"region-2-v4": []probe{p("2a", 4), p("2b", 4, 100*ms), p("2a", 4, 200*ms)}, // a -> b -> a
				"region-3-v4": []probe{p("3a", 4), p("3b", 4, 100*ms), p("3c", 4, 200*ms)}, // a -> b -> c
				"region-4-v4": []probe{p("4a", 4), p("4b", 4, 100*ms), p("4c", 4, 200*ms)},
				"region-5-v4": []probe{p("5a", 4), p("5b", 4, 100*ms), p("5c", 4, 200*ms)},
			},
		},
		{
			name:    "second_v4_no_6if",
			dm:      basicMap,
			have6if: false,
			last: &Report{
				RegionLatency: map[int]time.Duration{
					1: 10 * time.Millisecond,
					2: 20 * time.Millisecond,
					3: 30 * time.Millisecond,
					4: 40 * time.Millisecond,
					// Pretend 5 is missing
				},
				RegionV4Latency: map[int]time.Duration{
					1: 10 * time.Millisecond,
					2: 20 * time.Millisecond,
					3: 30 * time.Millisecond,
					4: 40 * time.Millisecond,
				},
			},
			want: probePlan{
				"region-1-v4": []probe{p("1a", 4), p("1a", 4, 12*ms)},
				"region-2-v4": []probe{p("2a", 4), p("2b", 4, 24*ms)},
				"region-3-v4": []probe{p("3a", 4)},
			},
		},
		{
			name:    "second_v4_only_with_6if",
			dm:      basicMap,
			have6if: true,
			last: &Report{
				RegionLatency: map[int]time.Duration{
					1: 10 * time.Millisecond,
					2: 20 * time.Millisecond,
					3: 30 * time.Millisecond,
					4: 40 * time.Millisecond,
					// Pretend 5 is missing
				},
				RegionV4Latency: map[int]time.Duration{
					1: 10 * time.Millisecond,
					2: 20 * time.Millisecond,
					3: 30 * time.Millisecond,
					4: 40 * time.Millisecond,
				},
			},
			want: probePlan{
				"region-1-v4": []probe{p("1a", 4), p("1a", 4, 12*ms)},
				"region-1-v6": []probe{p("1a", 6)},
				"region-2-v4": []probe{p("2a", 4), p("2b", 4, 24*ms)},
				"region-2-v6": []probe{p("2a", 6)},
				"region-3-v4": []probe{p("3a", 4)},
			},
		},
		{
			name:    "second_mixed",
			dm:      basicMap,
			have6if: true,
			last: &Report{
				RegionLatency: map[int]time.Duration{
					1: 10 * time.Millisecond,
					2: 20 * time.Millisecond,
					3: 30 * time.Millisecond,
					4: 40 * time.Millisecond,
					// Pretend 5 is missing
				},
				RegionV4Latency: map[int]time.Duration{
					1: 10 * time.Millisecond,
					2: 20 * time.Millisecond,
				},
				RegionV6Latency: map[int]time.Duration{
					3: 30 * time.Millisecond,
					4: 40 * time.Millisecond,
				},
			},
			want: probePlan{
				"region-1-v4": []probe{p("1a", 4), p("1a", 4, 12*ms)},
				"region-1-v6": []probe{p("1a", 6), p("1a", 6, 12*ms)},
				"region-2-v4": []probe{p("2a", 4), p("2b", 4, 24*ms)},
				"region-2-v6": []probe{p("2a", 6), p("2b", 6, 24*ms)},
				"region-3-v4": []probe{p("3a", 4)},
			},
		},
		{
			name:    "only_v6_initial",
			have6if: true,
			no4:     true,
			dm:      basicMap,
			want: probePlan{
				"region-1-v6": []probe{p("1a", 6), p("1a", 6, 100*ms), p("1a", 6, 200*ms)},
				"region-2-v6": []probe{p("2a", 6), p("2b", 6, 100*ms), p("2a", 6, 200*ms)},
				"region-3-v6": []probe{p("3a", 6), p("3b", 6, 100*ms), p("3c", 6, 200*ms)},
				"region-4-v6": []probe{p("4a", 6), p("4b", 6, 100*ms), p("4c", 6, 200*ms)},
				"region-5-v6": []probe{p("5a", 6), p("5b", 6, 100*ms), p("5c", 6, 200*ms)},
			},
		},
		{
			name:    "try_harder_for_preferred_derp",
			dm:      basicMap,
			have6if: true,
			last: &Report{
				RegionLatency: map[int]time.Duration{
					1: 10 * time.Millisecond,
					2: 20 * time.Millisecond,
					3: 30 * time.Millisecond,
					4: 40 * time.Millisecond,
				},
				RegionV4Latency: map[int]time.Duration{
					1: 10 * time.Millisecond,
					2: 20 * time.Millisecond,
				},
				RegionV6Latency: map[int]time.Duration{
					3: 30 * time.Millisecond,
					4: 40 * time.Millisecond,
				},
				PreferredDERP: 1,
			},
			want: probePlan{
				"region-1-v4": []probe{p("1a", 4), p("1a", 4, 12*ms), p("1a", 4, 124*ms), p("1a", 4, 186*ms)},
				"region-1-v6": []probe{p("1a", 6), p("1a", 6, 12*ms), p("1a", 6, 124*ms), p("1a", 6, 186*ms)},
				"region-2-v4": []probe{p("2a", 4), p("2b", 4, 24*ms)},
				"region-2-v6": []probe{p("2a", 6), p("2b", 6, 24*ms)},
				"region-3-v4": []probe{p("3a", 4)},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ifState := &netmon.State{
				HaveV6: tt.have6if,
				HaveV4: !tt.no4,
			}
			got := makeProbePlan(tt.dm, ifState, tt.last)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unexpected plan; got:\n%v\nwant:\n%v\n", got, tt.want)
			}
		})
	}
}

func (plan probePlan) String() string {
	var sb strings.Builder
	for _, key := range slices.Sorted(maps.Keys(plan)) {
		fmt.Fprintf(&sb, "[%s]", key)
		pv := plan[key]
		for _, p := range pv {
			fmt.Fprintf(&sb, " %v", p)
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}

func (p probe) String() string {
	wait := ""
	if p.wait > 0 {
		wait = "+" + p.wait.String()
	}
	delay := ""
	if p.delay > 0 {
		delay = "@" + p.delay.String()
	}
	return fmt.Sprintf("%s-%s%s%s", p.node, p.proto, delay, wait)
}

func TestLogConciseReport(t *testing.T) {
	dm := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: nil,
			2: nil,
			3: nil,
		},
	}
	const ms = time.Millisecond
	tests := []struct {
		name string
		r    *Report
		want string
	}{
		{
			name: "no_udp",
			r:    &Report{},
			want: "udp=false v4=false icmpv4=false v6=false mapvarydest= portmap=? derp=0",
		},
		{
			name: "no_udp_icmp",
			r:    &Report{ICMPv4: true, IPv4: true},
			want: "udp=false icmpv4=true v6=false mapvarydest= portmap=? derp=0",
		},
		{
			name: "ipv4_one_region",
			r: &Report{
				UDP:           true,
				IPv4:          true,
				PreferredDERP: 1,
				RegionLatency: map[int]time.Duration{
					1: 10 * ms,
				},
				RegionV4Latency: map[int]time.Duration{
					1: 10 * ms,
				},
			},
			want: "udp=true v6=false mapvarydest= portmap=? derp=1 derpdist=1v4:10ms",
		},
		{
			name: "ipv4_all_region",
			r: &Report{
				UDP:           true,
				IPv4:          true,
				PreferredDERP: 1,
				RegionLatency: map[int]time.Duration{
					1: 10 * ms,
					2: 20 * ms,
					3: 30 * ms,
				},
				RegionV4Latency: map[int]time.Duration{
					1: 10 * ms,
					2: 20 * ms,
					3: 30 * ms,
				},
			},
			want: "udp=true v6=false mapvarydest= portmap=? derp=1 derpdist=1v4:10ms,2v4:20ms,3v4:30ms",
		},
		{
			name: "ipboth_all_region",
			r: &Report{
				UDP:           true,
				IPv4:          true,
				IPv6:          true,
				PreferredDERP: 1,
				RegionLatency: map[int]time.Duration{
					1: 10 * ms,
					2: 20 * ms,
					3: 30 * ms,
				},
				RegionV4Latency: map[int]time.Duration{
					1: 10 * ms,
					2: 20 * ms,
					3: 30 * ms,
				},
				RegionV6Latency: map[int]time.Duration{
					1: 10 * ms,
					2: 20 * ms,
					3: 30 * ms,
				},
			},
			want: "udp=true v6=true mapvarydest= portmap=? derp=1 derpdist=1v4:10ms,1v6:10ms,2v4:20ms,2v6:20ms,3v4:30ms,3v6:30ms",
		},
		{
			name: "portmap_all",
			r: &Report{
				UDP:  true,
				UPnP: "true",
				PMP:  "true",
				PCP:  "true",
			},
			want: "udp=true v4=false v6=false mapvarydest= portmap=UMC derp=0",
		},
		{
			name: "portmap_some",
			r: &Report{
				UDP:  true,
				UPnP: "true",
				PMP:  "false",
				PCP:  "true",
			},
			want: "udp=true v4=false v6=false mapvarydest= portmap=UC derp=0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			c := &Client{Logf: func(f string, a ...any) { fmt.Fprintf(&buf, f, a...) }}
			c.logConciseReport(tt.r, dm)
			if got, ok := strings.CutPrefix(buf.String(), "[v1] report: "); !ok {
				t.Errorf("unexpected result.\n got: %#q\nwant: %#q\n", got, tt.want)
			}
		})
	}
}

func TestSortRegions(t *testing.T) {
	unsortedMap := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{},
	}
	for rid := 1; rid <= 5; rid++ {
		var nodes []*tailcfg.DERPNode
		nodes = append(nodes, &tailcfg.DERPNode{
			Name:     fmt.Sprintf("%da", rid),
			RegionID: rid,
			HostName: fmt.Sprintf("derp%d-1", rid),
			IPv4:     fmt.Sprintf("%d.0.0.1", rid),
			IPv6:     fmt.Sprintf("%d::1", rid),
		})
		unsortedMap.Regions[rid] = &tailcfg.DERPRegion{
			RegionID: rid,
			Nodes:    nodes,
		}
	}
	report := newReport()
	report.RegionLatency[1] = time.Second * time.Duration(5)
	report.RegionLatency[2] = time.Second * time.Duration(3)
	report.RegionLatency[3] = time.Second * time.Duration(6)
	report.RegionLatency[4] = time.Second * time.Duration(0)
	report.RegionLatency[5] = time.Second * time.Duration(2)
	sortedMap := sortRegions(unsortedMap, report)

	// Sorting by latency this should result in rid: 5, 2, 1, 3
	// rid 4 with latency 0 should be at the end
	want := []int{5, 2, 1, 3, 4}
	got := make([]int, len(sortedMap))
	for i, r := range sortedMap {
		got[i] = r.RegionID
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}
}

type RoundTripFunc func(req *http.Request) *http.Response

func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func TestNodeAddrResolve(t *testing.T) {
	nettest.SkipIfNoNetwork(t)
	c := &Client{
		Logf:        t.Logf,
		UseDNSCache: true,
	}

	dn := &tailcfg.DERPNode{
		Name:     "derptest1a",
		RegionID: 901,
		HostName: "tailscale.com",
		// No IPv4 or IPv6 addrs
	}
	dnV4Only := &tailcfg.DERPNode{
		Name:     "derptest1b",
		RegionID: 901,
		HostName: "ipv4.google.com",
		// No IPv4 or IPv6 addrs
	}

	// Checks whether IPv6 and IPv6 DNS resolution works on this platform.
	ipv6Works := func(t *testing.T) bool {
		// Verify that we can create an IPv6 socket.
		ln, err := net.ListenPacket("udp6", "[::1]:0")
		if err != nil {
			t.Logf("IPv6 may not work on this machine: %v", err)
			return false
		}
		ln.Close()

		// Resolve a hostname that we know has an IPv6 address.
		addrs, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip6", "google.com")
		if err != nil {
			t.Logf("IPv6 DNS resolution error: %v", err)
			return false
		}
		if len(addrs) == 0 {
			t.Logf("IPv6 DNS resolution returned no addresses")
			return false
		}
		return true
	}

	ctx := context.Background()
	for _, tt := range []bool{true, false} {
		t.Run(fmt.Sprintf("UseDNSCache=%v", tt), func(t *testing.T) {
			c.resolver = nil
			c.UseDNSCache = tt

			t.Run("IPv4", func(t *testing.T) {
				ap := c.nodeAddr(ctx, dn, probeIPv4)
				if !ap.IsValid() {
					t.Fatal("expected valid AddrPort")
				}
				if !ap.Addr().Is4() {
					t.Fatalf("expected IPv4 addr, got: %v", ap.Addr())
				}
				t.Logf("got IPv4 addr: %v", ap)
			})
			t.Run("IPv6", func(t *testing.T) {
				// Skip if IPv6 doesn't work on this machine.
				if !ipv6Works(t) {
					t.Skipf("IPv6 may not work on this machine")
				}

				ap := c.nodeAddr(ctx, dn, probeIPv6)
				if !ap.IsValid() {
					t.Fatal("expected valid AddrPort")
				}
				if !ap.Addr().Is6() {
					t.Fatalf("expected IPv6 addr, got: %v", ap.Addr())
				}
				t.Logf("got IPv6 addr: %v", ap)
			})
			t.Run("IPv6 Failure", func(t *testing.T) {
				ap := c.nodeAddr(ctx, dnV4Only, probeIPv6)
				if ap.IsValid() {
					t.Fatalf("expected no addr but got: %v", ap)
				}
				t.Logf("correctly got invalid addr")
			})
		})
	}
}
