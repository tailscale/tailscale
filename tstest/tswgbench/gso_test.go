// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package tswgbench

import (
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest/tswgbench/netbench"
)

// TestLeanGSOVerify checks tswg's encryption straight from GSO packets
// (which builds each segment's headers itself, rather than segmenting with
// skb_gso_segment) against the kernel's own segmentation: with the
// module's verify_gso parameter set, each segment it builds is compared
// with skb_gso_segment's, checksums included. It sends TCP (GSO from TCP
// segmentation offload) and UDP with UDP_SEGMENT (UDP GSO), over IPv4 and
// IPv6.
func TestLeanGSOVerify(t *testing.T) {
	l := newLab(t, 4)
	for _, v6 := range []bool{false, true} {
		ip := l.setup(modeTSWG, v6)
		addr := netip.AddrPortFrom(ip, benchPort)
		sender, receiver := benchNode{l.vms[0]}, benchNode{l.vms[1]}
		if err := receiver.Do("POST", fmt.Sprintf("serve?port=%d", benchPort), nil); err != nil {
			t.Fatal(err)
		}
		if err := l.vms[0].do("POST", "/param?name=verify_gso&value=1", nil); err != nil {
			t.Fatal(err)
		}
		param := func(name string) int {
			t.Helper()
			s := l.vms[0].getText("/file?path=/sys/module/tswg/parameters/" + name)
			n, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil {
				t.Fatalf("%s: %q", name, s)
			}
			return n
		}
		check := func(load string, run func() error) {
			t.Helper()
			verified, errs := param("gso_verified"), param("gso_verify_errors")
			if err := run(); err != nil {
				t.Fatalf("v6=%v %s: %v", v6, load, err)
			}
			verified, errs = param("gso_verified")-verified, param("gso_verify_errors")-errs
			t.Logf("v6=%v %s: %d segments verified, %d GSO packets differed", v6, load, verified, errs)
			if verified == 0 {
				t.Errorf("v6=%v %s: no segments verified; were any GSO packets encrypted whole?", v6, load)
			}
			if errs != 0 {
				t.Errorf("v6=%v %s: %d GSO packets' segments differed from skb_gso_segment's (see dmesg)", v6, load, errs)
			}
		}
		check("tcp", func() error {
			r, err := netbench.RunTCP(sender, receiver, addr, 1, 3*time.Second)
			if err == nil && r.Mbps == 0 {
				err = fmt.Errorf("no throughput")
			}
			return err
		})
		check("udp gso", func() error {
			r, err := netbench.RunUDPGSO(sender, receiver, addr, 11*1100, 1100, 2*time.Second)
			if err == nil && r.ReceivedPPS == 0 {
				err = fmt.Errorf("nothing received")
			}
			return err
		})
	}
}

// TestLeanGSOVerifyForwarded is like TestLeanGSOVerify, but for packets
// that tswg's host forwards rather than sends, as a subnet router does: VM
// 1 has a LAN host behind it (the agent's /lan-netns, a network namespace
// whose packets VM 1's GRO merges), and forwards its traffic to VM 0
// through the tunnel.
func TestLeanGSOVerifyForwarded(t *testing.T) {
	l := newLab(t, 4)
	l.setupExtra = func(i int, q url.Values) {
		if i == 0 {
			q.Set("allowed-ips", q.Get("allowed-ips")+",192.168.77.0/24,fd78::/64")
			q.Add("route", "192.168.77.0/24")
			q.Add("route", "fd78::/64")
		}
	}
	fwd := l.vms[1]
	for _, v6 := range []bool{false, true} {
		l.setup(modeTSWG, v6)
		if err := fwd.do("POST", "/lan-netns", nil); err != nil {
			t.Fatal(err)
		}

		sender, receiver := benchNode{fwd}, benchNode{l.vms[0]}
		if err := receiver.Do("POST", fmt.Sprintf("serve?port=%d", benchPort), nil); err != nil {
			t.Fatal(err)
		}
		if err := fwd.do("POST", "/param?name=verify_gso&value=1", nil); err != nil {
			t.Fatal(err)
		}
		param := func(name string) int {
			t.Helper()
			s := fwd.getText("/file?path=/sys/module/tswg/parameters/" + name)
			n, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil {
				t.Fatalf("%s: %q", name, s)
			}
			return n
		}
		dst := tunnel4(0)
		if v6 {
			dst = tunnel6(0)
		}
		verified, errs := param("gso_verified"), param("gso_verify_errors")
		r, err := netbench.RunTCPFrom(sender, "lan", receiver, netip.AddrPortFrom(dst, benchPort), 4, 3*time.Second)
		if err != nil {
			t.Fatalf("v6=%v: %v", v6, err)
		}
		verified, errs = param("gso_verified")-verified, param("gso_verify_errors")-errs
		t.Logf("v6=%v: %.0f Mbps forwarded; %d segments verified, %d GSO packets differed", v6, r.Mbps, verified, errs)
		if r.Mbps == 0 || verified == 0 {
			t.Errorf("v6=%v: nothing forwarded as GSO packets (%.0f Mbps, %d segments verified)", v6, r.Mbps, verified)
		}
		if errs != 0 {
			t.Errorf("v6=%v: %d GSO packets' segments differed from skb_gso_segment's (see dmesg)", v6, errs)
		}
	}
}

// TestLeanForwardCompare compares forwarding through tswg, as in
// TestLeanGSOVerifyForwarded, with a module parameter (TSWG_FORWARD_PARAM,
// default gso_whole; see tswg_gso_whole_ok) set to each of
// TSWG_FORWARD_VALUES (comma-separated, default "1,0"):
// TSWG_COMPARE_RUNS (default 4) runs of each, interleaved, of
// TSWG_COMPARE_STREAMS (default 4) TCP streams.
// VM 1's CPU per GB includes the LAN host's sending. TSWG_FORWARD_PROFILE
// names a value during whose last run to profile VM 1, with
// TSWG_PROFILE_FOCUS as in TestLeanProfile.
func TestLeanForwardCompare(t *testing.T) {
	if os.Getenv("TSWG_LEAN_FORWARD") == "" {
		t.Skip("set TSWG_LEAN_FORWARD=1 (and TSWG_LEAN=1) to run")
	}
	runs, streams := 4, 4
	if n, err := strconv.Atoi(os.Getenv("TSWG_COMPARE_RUNS")); err == nil {
		runs = n
	}
	if n, err := strconv.Atoi(os.Getenv("TSWG_COMPARE_STREAMS")); err == nil {
		streams = n
	}
	param := os.Getenv("TSWG_FORWARD_PARAM")
	if param == "" {
		param = "gso_whole"
	}
	values := []string{"1", "0"}
	if v := os.Getenv("TSWG_FORWARD_VALUES"); v != "" {
		values = strings.Split(v, ",")
	}
	l := newLab(t, 4)
	l.setupExtra = func(i int, q url.Values) {
		if i == 0 {
			q.Set("allowed-ips", q.Get("allowed-ips")+",192.168.77.0/24")
			q.Add("route", "192.168.77.0/24")
		}
	}
	fwd := l.vms[1]
	l.setup(modeTSWG, false)
	if err := fwd.do("POST", "/lan-netns", nil); err != nil {
		t.Fatal(err)
	}
	sender, receiver := benchNode{fwd}, benchNode{l.vms[0]}
	if err := receiver.Do("POST", fmt.Sprintf("serve?port=%d", benchPort), nil); err != nil {
		t.Fatal(err)
	}
	type res struct{ mbps, cpu []float64 }
	results := map[string]*res{}
	for _, v := range values {
		results[v] = &res{}
	}
	for run := range runs {
		for _, whole := range values {
			if err := fwd.do("POST", "/param?name="+param+"&value="+whole, nil); err != nil {
				t.Fatal(err)
			}
			var prof profileResult
			profDone := make(chan error, 1)
			profiling := run == runs-1 && whole == os.Getenv("TSWG_FORWARD_PROFILE")
			if profiling {
				go func() {
					time.Sleep(time.Second)
					profDone <- fwd.do("GET", "/profile?"+url.Values{
						"dur":   {"3s"},
						"top":   {"50"},
						"focus": {os.Getenv("TSWG_PROFILE_FOCUS")},
					}.Encode(), &prof)
				}()
			}
			r, err := netbench.RunTCPFrom(sender, "lan", receiver, netip.AddrPortFrom(tunnel4(0), benchPort), streams, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if profiling {
				if err := <-profDone; err != nil {
					t.Fatal(err)
				}
				t.Logf("VM 1 profile, %s=%s:\n%s", param, whole, formatProfile(prof))
			}
			t.Logf("run %d: %s=%s: %.0f Mbps, forwarder %.2f CPU-s/GB", run, param, whole, r.Mbps, r.SenderCPUSecPerGB)
			results[whole].mbps = append(results[whole].mbps, r.Mbps)
			results[whole].cpu = append(results[whole].cpu, r.SenderCPUSecPerGB)
		}
	}
	median := func(v []float64) float64 { return slices.Sorted(slices.Values(v))[len(v)/2] }
	for _, whole := range values {
		t.Logf("%s=%s: median %.0f Mbps, forwarder %.2f CPU-s/GB", param, whole, median(results[whole].mbps), median(results[whole].cpu))
	}
}
