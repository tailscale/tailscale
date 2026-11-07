// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

// These mirror the JSON types of tta's /tswg/bench/ endpoints.
type (
	benchStats struct{ TCPBytes, UDPPackets, UDPBytes int64 }
	benchCPU   struct {
		Busy, Total int64
		NumCPU      int
	}
	benchClientResult struct {
		Bytes, Packets int64
		Seconds        float64
	}
	benchRTT struct {
		Samples, Lost            int
		P50, P90, P99, Max, Mean float64
	}
)

// benchTCPResult is the result of one TCP throughput run.
type benchTCPResult struct {
	Mbps float64 // as received
	// CPU use during the run on the sender and receiver, as a fraction of
	// all of the VM's CPUs.
	SenderCPU, ReceiverCPU float64
	// CPU seconds per gigabyte received, on the sender and receiver.
	SenderCPUSecPerGB, ReceiverCPUSecPerGB float64
}

// benchUDPResult is the result of one small-packet UDP run.
type benchUDPResult struct {
	SentPPS, ReceivedPPS float64
	Loss                 float64 // fraction of sent packets not received
	ReceiverCPU          float64 // as in benchTCPResult
	// Receiver CPU microseconds per received packet.
	ReceiverCPUMicrosPerPacket float64
}

// benchModeResult is the benchmark results for one data plane.
type benchModeResult struct {
	TCP1, TCP4        benchTCPResult // 1 and 4 streams
	UDP64             benchUDPResult // 64-byte datagrams
	RTTIdle, RTTUnder benchRTT       // idle, and under a 1-stream TCP load
}

// benchUserHZ is the kernel's USER_HZ, the unit of /proc/stat.
const benchUserHZ = 100

func (f *tswgTailscaled) cpu(n *vmtest.Node) benchCPU {
	f.t.Helper()
	var c benchCPU
	f.unmarshalTTA(n, "GET", "/tswg/bench/cpu", &c)
	return c
}

func (f *tswgTailscaled) benchStats(n *vmtest.Node) benchStats {
	f.t.Helper()
	var s benchStats
	f.unmarshalTTA(n, "GET", "/tswg/bench/stats", &s)
	return s
}

func (f *tswgTailscaled) unmarshalTTA(n *vmtest.Node, method, path string, v any) {
	f.t.Helper()
	res, err := ttaErrTimeout(n, method, path, nil, 5*time.Minute)
	if err != nil {
		f.t.Fatalf("[%s] %v", n.Name(), err)
	}
	if err := json.Unmarshal([]byte(res), v); err != nil {
		f.t.Fatalf("[%s] %s %s: %v", n.Name(), method, path, err)
	}
}

// cpuUse returns the CPU used between two snapshots: as a fraction of all
// CPUs, and in CPU seconds.
func cpuUse(before, after benchCPU) (frac, secs float64) {
	busy, total := after.Busy-before.Busy, after.Total-before.Total
	if total <= 0 {
		return 0, 0
	}
	return float64(busy) / float64(total), float64(busy) / benchUserHZ
}

// benchTCP runs a TCP throughput test from n1 to n2 at addr.
func (f *tswgTailscaled) benchTCP(n1, n2 *vmtest.Node, addr netip.AddrPort, streams int, dur time.Duration) benchTCPResult {
	f.t.Helper()
	c1, c2, s2 := f.cpu(n1), f.cpu(n2), f.benchStats(n2)
	var res benchClientResult
	f.unmarshalTTA(n1, "GET", "/tswg/bench/tcp?"+url.Values{
		"addr":    {addr.String()},
		"dur":     {dur.String()},
		"streams": {strconv.Itoa(streams)},
	}.Encode(), &res)
	time.Sleep(500 * time.Millisecond) // let in-flight data land
	c1b, c2b, s2b := f.cpu(n1), f.cpu(n2), f.benchStats(n2)

	rx := float64(s2b.TCPBytes - s2.TCPBytes)
	r := benchTCPResult{Mbps: rx * 8 / res.Seconds / 1e6}
	var sSecs, rSecs float64
	r.SenderCPU, sSecs = cpuUse(c1, c1b)
	r.ReceiverCPU, rSecs = cpuUse(c2, c2b)
	if rx > 0 {
		r.SenderCPUSecPerGB = sSecs / (rx / 1e9)
		r.ReceiverCPUSecPerGB = rSecs / (rx / 1e9)
	}
	return r
}

// benchUDP runs a small-packet UDP test from n1 to n2 at addr.
func (f *tswgTailscaled) benchUDP(n1, n2 *vmtest.Node, addr netip.AddrPort, size int, dur time.Duration) benchUDPResult {
	f.t.Helper()
	c2, s2 := f.cpu(n2), f.benchStats(n2)
	var res benchClientResult
	f.unmarshalTTA(n1, "GET", "/tswg/bench/udp?"+url.Values{
		"addr": {addr.String()},
		"dur":  {dur.String()},
		"size": {strconv.Itoa(size)},
	}.Encode(), &res)
	time.Sleep(500 * time.Millisecond)
	c2b, s2b := f.cpu(n2), f.benchStats(n2)

	rxPkts := float64(s2b.UDPPackets - s2.UDPPackets)
	r := benchUDPResult{
		SentPPS:     float64(res.Packets) / res.Seconds,
		ReceivedPPS: rxPkts / res.Seconds,
	}
	if res.Packets > 0 {
		r.Loss = 1 - rxPkts/float64(res.Packets)
	}
	var rSecs float64
	r.ReceiverCPU, rSecs = cpuUse(c2, c2b)
	if rxPkts > 0 {
		r.ReceiverCPUMicrosPerPacket = rSecs * 1e6 / rxPkts
	}
	return r
}

// benchRTT measures UDP round trips from n1 to the echo server at addr.
func (f *tswgTailscaled) benchRTT(n1 *vmtest.Node, addr netip.AddrPort, probes int) benchRTT {
	f.t.Helper()
	var r benchRTT
	f.unmarshalTTA(n1, "GET", "/tswg/bench/rtt?"+url.Values{
		"addr":     {addr.String()},
		"n":        {strconv.Itoa(probes)},
		"interval": {"5ms"},
	}.Encode(), &r)
	return r
}

// runBench runs the benchmark suite from f's first node to its second,
// over their direct path, which is on their shared LAN.
func (f *tswgTailscaled) runBench(kernelMode bool, dur time.Duration) *benchModeResult {
	f.t.Helper()
	n1, n2 := f.nodes[0], f.nodes[1]
	ip2 := f.ip(n2)
	if _, err := f.env.PingExpect(n1, n2, vmtest.PingRouteLocal, 60*time.Second); err != nil {
		f.t.Fatalf("no direct LAN path: %v", err)
	}
	if kernelMode {
		f.waitKernelPath(n1, ip2, true, 60*time.Second)
	}
	// And the tunnel actually carries traffic (waitKernelPath only looks
	// at the kernel's endpoint).
	f.env.LANPing(n1, ip2)
	tta(f.t, n2, "POST", "/tswg/bench/serve?port=5201", nil)
	addr := netip.AddrPortFrom(ip2, 5201)

	r := &benchModeResult{
		TCP1:    f.benchTCP(n1, n2, addr, 1, dur),
		TCP4:    f.benchTCP(n1, n2, addr, 4, dur),
		UDP64:   f.benchUDP(n1, n2, addr, 64, dur/2),
		RTTIdle: f.benchRTT(n1, addr, 400),
	}
	var wg sync.WaitGroup
	wg.Go(func() { f.benchTCP(n1, n2, addr, 1, 4*time.Second) })
	time.Sleep(500 * time.Millisecond) // let the load ramp up
	r.RTTUnder = f.benchRTT(n1, addr, 400)
	wg.Wait()
	return r
}

// TestTSWGBenchmark compares the tswg kernel data plane against
// wireguard-go (tailscaled's usual TUN mode) on the same pair of gokrazy
// VMs on one LAN: TCP throughput (1 and 4 streams) and the CPU it costs,
// small-packet UDP rate, and UDP round-trip latency, idle and under load.
//
// It's slow, so it only runs with TSWG_BENCH=1. TSWG_BENCH_CPUS sets each
// VM's virtual CPUs (default 2), TSWG_BENCH_DUR the length of each
// throughput run (default 10s), and TSWG_BENCH_OUT a file to write the
// results to as JSON.
//
// natlab's network is simulated in userspace on the host, which caps the
// absolute numbers; the CPU cost per byte and per packet inside the VMs,
// and the comparison between data planes, are what this measures.
func TestTSWGBenchmark(t *testing.T) {
	if os.Getenv("TSWG_BENCH") == "" {
		t.Skip("set TSWG_BENCH=1 to run")
	}
	cpus := 2
	if s := os.Getenv("TSWG_BENCH_CPUS"); s != "" {
		var err error
		if cpus, err = strconv.Atoi(s); err != nil {
			t.Fatalf("TSWG_BENCH_CPUS: %v", err)
		}
	}
	dur := 10 * time.Second
	if s := os.Getenv("TSWG_BENCH_DUR"); s != "" {
		var err error
		if dur, err = time.ParseDuration(s); err != nil {
			t.Fatalf("TSWG_BENCH_DUR: %v", err)
		}
	}

	ko := buildTSWGForGokrazy(t, tswgDir(t))
	f := &tswgTailscaled{t: t, env: vmtest.New(t)}
	lan := f.env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT)
	for i := range 2 {
		f.nodes = append(f.nodes, f.env.AddNode(fmt.Sprintf("tswg%d", i+1), lan,
			vmtest.OS(vmtest.Gokrazy),
			vmtest.CPUs(cpus),
			vnet.TailscaledEnv{Key: "TS_DEBUG_TSWG", Value: "1"}))
	}
	f.env.Start()

	// tailscaled starts in TUN mode (wireguard-go), since the module isn't
	// loaded yet.
	for _, n := range f.nodes {
		if _, err := f.show(n); err == nil {
			t.Fatalf("[%s] has a tswg device before the module was loaded", n.Name())
		}
	}
	results := map[string]*benchModeResult{}
	t.Logf("benchmarking wireguard-go...")
	results["wireguard-go"] = f.runBench(false, dur)

	for _, n := range f.nodes {
		tta(t, n, "POST", "/tswg/load", ko)
		f.env.RestartTailscaled(n)
	}
	for _, n := range f.nodes {
		f.waitKernelReady(n)
	}
	t.Logf("benchmarking tswg...")
	results["tswg"] = f.runBench(true, dur)

	t.Logf("results (%d vCPUs per VM, %v runs):\n%s", cpus, dur, formatBenchResults(results["wireguard-go"], results["tswg"]))
	if out := os.Getenv("TSWG_BENCH_OUT"); out != "" {
		j, err := json.MarshalIndent(map[string]any{
			"cpus":    cpus,
			"dur":     dur.String(),
			"results": results,
		}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, j, 0644); err != nil {
			t.Fatal(err)
		}
	}
}

// formatBenchResults formats the results for the two data planes as a
// table.
func formatBenchResults(wg, k *benchModeResult) string {
	var sb strings.Builder
	row := func(name, unit string, a, b float64, lowerIsBetter bool) {
		ratio := "-"
		if a != 0 {
			ratio = fmt.Sprintf("%.2fx", b/a)
		}
		better := "higher is better"
		if lowerIsBetter {
			better = "lower is better"
		}
		fmt.Fprintf(&sb, "  %-36s %12.2f %12.2f %8s  %s (%s)\n", name, a, b, ratio, unit, better)
	}
	fmt.Fprintf(&sb, "  %-36s %12s %12s %8s\n", "", "wireguard-go", "tswg", "tswg/wg")
	for _, x := range []struct {
		name  string
		wg, k benchTCPResult
	}{{"TCP 1 stream", wg.TCP1, k.TCP1}, {"TCP 4 streams", wg.TCP4, k.TCP4}} {
		row(x.name+" throughput", "Mbps", x.wg.Mbps, x.k.Mbps, false)
		row(x.name+" sender CPU", "% of VM", x.wg.SenderCPU*100, x.k.SenderCPU*100, true)
		row(x.name+" receiver CPU", "% of VM", x.wg.ReceiverCPU*100, x.k.ReceiverCPU*100, true)
		row(x.name+" sender CPU per GB", "CPU-s/GB", x.wg.SenderCPUSecPerGB, x.k.SenderCPUSecPerGB, true)
		row(x.name+" receiver CPU per GB", "CPU-s/GB", x.wg.ReceiverCPUSecPerGB, x.k.ReceiverCPUSecPerGB, true)
	}
	row("UDP 64B sent", "pps", wg.UDP64.SentPPS, k.UDP64.SentPPS, false)
	row("UDP 64B received", "pps", wg.UDP64.ReceivedPPS, k.UDP64.ReceivedPPS, false)
	row("UDP 64B loss", "%", wg.UDP64.Loss*100, k.UDP64.Loss*100, true)
	row("UDP 64B receiver CPU per packet", "us", wg.UDP64.ReceiverCPUMicrosPerPacket, k.UDP64.ReceiverCPUMicrosPerPacket, true)
	row("RTT idle p50", "ms", wg.RTTIdle.P50, k.RTTIdle.P50, true)
	row("RTT idle p99", "ms", wg.RTTIdle.P99, k.RTTIdle.P99, true)
	row("RTT under TCP load p50", "ms", wg.RTTUnder.P50, k.RTTUnder.P50, true)
	row("RTT under TCP load p99", "ms", wg.RTTUnder.P99, k.RTTUnder.P99, true)
	return sb.String()
}
