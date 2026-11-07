// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netbench

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Node is a VM running the benchmark endpoints (see Register).
type Node interface {
	// Do makes an HTTP request for the benchmark endpoint path (such as
	// "tcp?addr=..."; relative to the prefix passed to Register) and, if
	// v is non-nil, decodes the JSON response into v.
	Do(method, path string, v any) error
}

// TCPResult is the result of one TCP throughput run.
type TCPResult struct {
	Mbps float64 // as received
	// CPU use during the run on the sender and receiver, as a fraction of
	// all of the VM's CPUs.
	SenderCPU, ReceiverCPU float64
	// CPU seconds per gigabyte received, on the sender and receiver.
	SenderCPUSecPerGB, ReceiverCPUSecPerGB float64
}

// UDPResult is the result of one small-packet UDP run.
type UDPResult struct {
	SentPPS, ReceivedPPS float64
	Loss                 float64 // fraction of sent packets not received
	ReceiverCPU          float64 // as in TCPResult
	// Receiver CPU microseconds per received packet.
	ReceiverCPUMicrosPerPacket float64
}

// SuiteResult is the result of RunSuite.
type SuiteResult struct {
	TCP1, TCP4        TCPResult // 1 and 4 streams
	UDP64             UDPResult // 64-byte datagrams
	RTTIdle, RTTUnder RTT       // idle, and under a 1-stream TCP load
}

// userHZ is the kernel's USER_HZ, the unit of /proc/stat.
const userHZ = 100

// cpuUse returns the CPU used between two snapshots: as a fraction of all
// CPUs, and in CPU seconds.
func cpuUse(before, after CPU) (frac, secs float64) {
	busy, total := after.Busy-before.Busy, after.Total-before.Total
	if total <= 0 {
		return 0, 0
	}
	return float64(busy) / float64(total), float64(busy) / userHZ
}

// settle is how long to wait after a run for in-flight data to land
// before reading the receiver's counters.
const settle = 500 * time.Millisecond

// RunTCP runs a TCP throughput test from sender to receiver, whose sink
// is at addr.
func RunTCP(sender, receiver Node, addr netip.AddrPort, streams int, dur time.Duration) (TCPResult, error) {
	var c1, c2, c1b, c2b CPU
	var s2, s2b Stats
	var res Result
	err := do(
		func() error { return sender.Do("GET", "cpu", &c1) },
		func() error { return receiver.Do("GET", "cpu", &c2) },
		func() error { return receiver.Do("GET", "stats", &s2) },
		func() error {
			return sender.Do("GET", "tcp?"+url.Values{
				"addr":    {addr.String()},
				"dur":     {dur.String()},
				"streams": {strconv.Itoa(streams)},
			}.Encode(), &res)
		},
		func() error { time.Sleep(settle); return nil },
		func() error { return sender.Do("GET", "cpu", &c1b) },
		func() error { return receiver.Do("GET", "cpu", &c2b) },
		func() error { return receiver.Do("GET", "stats", &s2b) },
	)
	if err != nil {
		return TCPResult{}, err
	}
	rx := float64(s2b.TCPBytes - s2.TCPBytes)
	r := TCPResult{Mbps: rx * 8 / res.Seconds / 1e6}
	var sSecs, rSecs float64
	r.SenderCPU, sSecs = cpuUse(c1, c1b)
	r.ReceiverCPU, rSecs = cpuUse(c2, c2b)
	if rx > 0 {
		r.SenderCPUSecPerGB = sSecs / (rx / 1e9)
		r.ReceiverCPUSecPerGB = rSecs / (rx / 1e9)
	}
	return r, nil
}

// RunUDP runs a small-packet UDP test from sender to receiver, whose sink
// is at addr.
func RunUDP(sender, receiver Node, addr netip.AddrPort, size int, dur time.Duration) (UDPResult, error) {
	var c2, c2b CPU
	var s2, s2b Stats
	var res Result
	err := do(
		func() error { return receiver.Do("GET", "cpu", &c2) },
		func() error { return receiver.Do("GET", "stats", &s2) },
		func() error {
			return sender.Do("GET", "udp?"+url.Values{
				"addr": {addr.String()},
				"dur":  {dur.String()},
				"size": {strconv.Itoa(size)},
			}.Encode(), &res)
		},
		func() error { time.Sleep(settle); return nil },
		func() error { return receiver.Do("GET", "cpu", &c2b) },
		func() error { return receiver.Do("GET", "stats", &s2b) },
	)
	if err != nil {
		return UDPResult{}, err
	}
	rxPkts := float64(s2b.UDPPackets - s2.UDPPackets)
	r := UDPResult{
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
	return r, nil
}

// RunRTT measures UDP round trips from sender to the echo server at addr.
func RunRTT(sender Node, addr netip.AddrPort, probes int) (RTT, error) {
	var r RTT
	err := sender.Do("GET", "rtt?"+url.Values{
		"addr":     {addr.String()},
		"n":        {strconv.Itoa(probes)},
		"interval": {"5ms"},
	}.Encode(), &r)
	return r, err
}

// RunSuite runs the benchmark suite from sender to receiver over addr (an
// address of receiver's, reached over the data plane being measured):
// TCP throughput with 1 and 4 streams, a 64-byte UDP flood (for half of
// dur), and UDP round trips, idle and under a 1-stream TCP load. It starts
// receiver's server on addr's port.
func RunSuite(sender, receiver Node, addr netip.AddrPort, dur time.Duration) (*SuiteResult, error) {
	if err := receiver.Do("POST", fmt.Sprintf("serve?port=%d", addr.Port()), nil); err != nil {
		return nil, err
	}
	r := &SuiteResult{}
	var err error
	if r.TCP1, err = RunTCP(sender, receiver, addr, 1, dur); err != nil {
		return nil, fmt.Errorf("TCP 1 stream: %w", err)
	}
	if r.TCP4, err = RunTCP(sender, receiver, addr, 4, dur); err != nil {
		return nil, fmt.Errorf("TCP 4 streams: %w", err)
	}
	if r.UDP64, err = RunUDP(sender, receiver, addr, 64, dur/2); err != nil {
		return nil, fmt.Errorf("UDP: %w", err)
	}
	if r.RTTIdle, err = RunRTT(sender, addr, 400); err != nil {
		return nil, fmt.Errorf("RTT: %w", err)
	}
	var wg sync.WaitGroup
	var loadErr error
	wg.Go(func() { _, loadErr = RunTCP(sender, receiver, addr, 1, 4*time.Second) })
	time.Sleep(500 * time.Millisecond) // let the load ramp up
	r.RTTUnder, err = RunRTT(sender, addr, 400)
	wg.Wait()
	if err != nil {
		return nil, fmt.Errorf("RTT under load: %w", err)
	}
	if loadErr != nil {
		return nil, fmt.Errorf("TCP load for RTT: %w", loadErr)
	}
	return r, nil
}

// do runs fns in order, stopping at the first error.
func do(fns ...func() error) error {
	for _, fn := range fns {
		if err := fn(); err != nil {
			return err
		}
	}
	return nil
}

// FormatTable formats results as a table with one column per name, plus,
// for each column after the first, its ratio to the first.
func FormatTable(names []string, results []*SuiteResult) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "  %-36s", "")
	for _, n := range names {
		fmt.Fprintf(&sb, " %12s", n)
	}
	for _, n := range names[1:] {
		fmt.Fprintf(&sb, " %12s", n+"/"+names[0])
	}
	sb.WriteString("\n")
	row := func(name, unit string, lowerIsBetter bool, get func(*SuiteResult) float64) {
		fmt.Fprintf(&sb, "  %-36s", name)
		for _, r := range results {
			fmt.Fprintf(&sb, " %12.2f", get(r))
		}
		base := get(results[0])
		for _, r := range results[1:] {
			if base == 0 {
				fmt.Fprintf(&sb, " %12s", "-")
			} else {
				fmt.Fprintf(&sb, " %11.2fx", get(r)/base)
			}
		}
		better := "higher is better"
		if lowerIsBetter {
			better = "lower is better"
		}
		fmt.Fprintf(&sb, "  %s (%s)\n", unit, better)
	}
	for _, x := range []struct {
		name string
		get  func(*SuiteResult) TCPResult
	}{
		{"TCP 1 stream", func(r *SuiteResult) TCPResult { return r.TCP1 }},
		{"TCP 4 streams", func(r *SuiteResult) TCPResult { return r.TCP4 }},
	} {
		row(x.name+" throughput", "Mbps", false, func(r *SuiteResult) float64 { return x.get(r).Mbps })
		row(x.name+" sender CPU", "% of VM", true, func(r *SuiteResult) float64 { return x.get(r).SenderCPU * 100 })
		row(x.name+" receiver CPU", "% of VM", true, func(r *SuiteResult) float64 { return x.get(r).ReceiverCPU * 100 })
		row(x.name+" sender CPU per GB", "CPU-s/GB", true, func(r *SuiteResult) float64 { return x.get(r).SenderCPUSecPerGB })
		row(x.name+" receiver CPU per GB", "CPU-s/GB", true, func(r *SuiteResult) float64 { return x.get(r).ReceiverCPUSecPerGB })
	}
	row("UDP 64B sent", "pps", false, func(r *SuiteResult) float64 { return r.UDP64.SentPPS })
	row("UDP 64B received", "pps", false, func(r *SuiteResult) float64 { return r.UDP64.ReceivedPPS })
	row("UDP 64B loss", "%", true, func(r *SuiteResult) float64 { return r.UDP64.Loss * 100 })
	row("UDP 64B receiver CPU per packet", "us", true, func(r *SuiteResult) float64 { return r.UDP64.ReceiverCPUMicrosPerPacket })
	row("RTT idle p50", "ms", true, func(r *SuiteResult) float64 { return r.RTTIdle.P50 })
	row("RTT idle p99", "ms", true, func(r *SuiteResult) float64 { return r.RTTIdle.P99 })
	row("RTT under TCP load p50", "ms", true, func(r *SuiteResult) float64 { return r.RTTUnder.P50 })
	row("RTT under TCP load p99", "ms", true, func(r *SuiteResult) float64 { return r.RTTUnder.P99 })
	return sb.String()
}
