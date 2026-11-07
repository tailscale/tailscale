// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netbench

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// FanInResult is the result of RunTCPFanIn.
type FanInResult struct {
	Mbps       float64   // total, as received
	SenderMbps []float64 // each sender's, as sent
	// Fairness is Jain's fairness index of the senders' throughput: 1
	// when all got the same, down to 1/n when one got everything.
	Fairness float64

	// CPU use during the run on each of the watched nodes (such as a
	// router in the path), as a fraction of all of its CPUs, and in CPU
	// seconds per gigabyte received.
	WatchCPU, WatchCPUSecPerGB []float64
	ReceiverCPU                float64
	ReceiverCPUSecPerGB        float64
}

// RunTCPFanIn runs TCP throughput tests from all of senders at once, each
// with streams connections, to receiver, whose sink is at addr, and
// measures the CPU use of receiver and the watch nodes meanwhile.
func RunTCPFanIn(senders []Node, receiver Node, watch []Node, addr netip.AddrPort, streams int, dur time.Duration) (FanInResult, error) {
	cpuNodes := append([]Node{receiver}, watch...)
	before := make([]CPU, len(cpuNodes))
	after := make([]CPU, len(cpuNodes))
	snapshot := func(cpus []CPU) error {
		for i, n := range cpuNodes {
			if err := n.Do("GET", "cpu", &cpus[i]); err != nil {
				return err
			}
		}
		return nil
	}
	var s, sb Stats
	if err := snapshot(before); err != nil {
		return FanInResult{}, err
	}
	if err := receiver.Do("GET", "stats", &s); err != nil {
		return FanInResult{}, err
	}

	results := make([]Result, len(senders))
	errs := make([]error, len(senders))
	var wg sync.WaitGroup
	for i, n := range senders {
		wg.Go(func() {
			errs[i] = n.Do("GET", "tcp?"+url.Values{
				"addr":    {addr.String()},
				"dur":     {dur.String()},
				"streams": {strconv.Itoa(streams)},
			}.Encode(), &results[i])
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			return FanInResult{}, fmt.Errorf("sender %d: %w", i, err)
		}
	}
	time.Sleep(settle)
	if err := snapshot(after); err != nil {
		return FanInResult{}, err
	}
	if err := receiver.Do("GET", "stats", &sb); err != nil {
		return FanInResult{}, err
	}

	rx := float64(sb.TCPBytes - s.TCPBytes)
	r := FanInResult{Mbps: rx * 8 / dur.Seconds() / 1e6}
	var sum, sumSq float64
	for _, res := range results {
		mbps := 0.0
		if res.Seconds > 0 {
			mbps = float64(res.Bytes) * 8 / res.Seconds / 1e6
		}
		r.SenderMbps = append(r.SenderMbps, mbps)
		sum += mbps
		sumSq += mbps * mbps
	}
	if sumSq > 0 {
		r.Fairness = sum * sum / (float64(len(results)) * sumSq)
	}
	perGB := func(secs float64) float64 {
		if rx <= 0 {
			return 0
		}
		return secs / (rx / 1e9)
	}
	var secs float64
	r.ReceiverCPU, secs = cpuUse(before[0], after[0])
	r.ReceiverCPUSecPerGB = perGB(secs)
	for i := range watch {
		frac, secs := cpuUse(before[i+1], after[i+1])
		r.WatchCPU = append(r.WatchCPU, frac)
		r.WatchCPUSecPerGB = append(r.WatchCPUSecPerGB, perGB(secs))
	}
	return r, nil
}
