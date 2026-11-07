// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package tswgbench

import (
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/tstest/tswgbench/netbench"
)

// These mirror the agent's profile types.
type (
	profileSym struct {
		Sym              string
		Self, Inclusive  int
		SelfPct, InclPct float64
	}
	profileCPU struct {
		CPU     int
		Samples int
		Busy    float64
		Top     []profileSym
	}
	profileStack struct {
		Stack   []string
		Samples int
		Pct     float64
	}
	profileResult struct {
		Seconds       float64
		Samples, Busy int
		Top           []profileSym
		CPUs          []profileCPU
		Focus         []profileStack
	}
)

// TestLeanProfile profiles both VMs (kernel and the agent's own code, so
// wireguard-go too) while a load runs from VM 0 to VM 1 over each data plane
// in TSWG_LEAN_PROFILE (comma-separated modes, such as "tswg,wggo"), and
// prints where the CPU time goes. TSWG_PROFILE_LOAD is tcp (default),
// tcp4 (4 streams) or udp (64-byte datagrams); TSWG_BENCH_CPUS sets the
// vCPUs (default 4). TSWG_PROFILE_FOCUS names a symbol whose callers to
// report.
func TestLeanProfile(t *testing.T) {
	modes := os.Getenv("TSWG_LEAN_PROFILE")
	if modes == "" {
		t.Skip("set TSWG_LEAN_PROFILE=mode,... (and TSWG_LEAN=1) to run")
	}
	cpus := 4
	if s := os.Getenv("TSWG_BENCH_CPUS"); s != "" {
		cpus, _ = strconv.Atoi(s)
	}
	load := os.Getenv("TSWG_PROFILE_LOAD")
	if load == "" {
		load = "tcp"
	}
	focus := os.Getenv("TSWG_PROFILE_FOCUS")
	l := newLab(t, cpus)
	const profDur = 5 * time.Second
	for _, mode := range strings.Split(modes, ",") {
		addr := netip.AddrPortFrom(l.setup(mode, false), benchPort)
		sender, receiver := benchNode{l.vms[0]}, benchNode{l.vms[1]}
		if err := receiver.Do("POST", fmt.Sprintf("serve?port=%d", benchPort), nil); err != nil {
			t.Fatal(err)
		}
		loadDur := profDur + 3*time.Second
		var wg sync.WaitGroup
		var loadDesc string
		wg.Go(func() {
			var err error
			switch load {
			case "tcp", "tcp4":
				streams := 1
				if load == "tcp4" {
					streams = 4
				}
				var r netbench.TCPResult
				r, err = netbench.RunTCP(sender, receiver, addr, streams, loadDur)
				loadDesc = fmt.Sprintf("%.0f Mbps", r.Mbps)
			case "udp":
				var r netbench.UDPResult
				r, err = netbench.RunUDP(sender, receiver, addr, 64, loadDur)
				loadDesc = fmt.Sprintf("%.0f pps received", r.ReceivedPPS)
			}
			if err != nil {
				t.Errorf("load: %v", err)
			}
		})
		time.Sleep(time.Second) // let the load ramp up
		var profs [2]profileResult
		var pwg sync.WaitGroup
		for i, v := range l.vms {
			pwg.Go(func() {
				if err := v.do("GET", "/profile?"+url.Values{"dur": {profDur.String()}, "top": {"30"}, "focus": {focus}}.Encode(), &profs[i]); err != nil {
					t.Errorf("profiling VM %d: %v", i, err)
				}
			})
		}
		pwg.Wait()
		wg.Wait()
		for i, p := range profs {
			role := "sender"
			if i == 1 {
				role = "receiver"
			}
			t.Logf("%s, %s load (%s): %s (VM %d)\n%s", mode, load, loadDesc, role, i, formatProfile(p))
		}
	}
}

func formatProfile(p profileResult) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "  per-CPU busy:")
	for _, c := range p.CPUs {
		fmt.Fprintf(&sb, " cpu%d=%.0f%%", c.CPU, c.Busy*100)
	}
	fmt.Fprintf(&sb, "\n  %6s %6s  %s\n", "self%", "incl%", "symbol (of non-idle samples)")
	for _, s := range p.Top {
		fmt.Fprintf(&sb, "  %6.2f %6.2f  %s\n", s.SelfPct, s.InclPct, s.Sym)
	}
	for _, c := range p.CPUs {
		fmt.Fprintf(&sb, "  cpu%d top:", c.CPU)
		for i, s := range c.Top {
			if i == 5 {
				break
			}
			fmt.Fprintf(&sb, " %s(%.0f%%)", s.Sym, s.SelfPct)
		}
		sb.WriteString("\n")
	}
	for _, st := range p.Focus {
		fmt.Fprintf(&sb, "  %5.2f%%  %s\n", st.Pct, strings.Join(st.Stack, " < "))
	}
	return sb.String()
}
