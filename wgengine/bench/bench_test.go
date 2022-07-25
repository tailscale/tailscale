// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Create two wgengine instances and pass data through them, measuring
// throughput, latency, and packet loss.
package main

import (
	"fmt"
	"testing"
	"time"

	"tailscale.com/types/logger"
)

func BenchmarkTrivialNoAlloc(b *testing.B) {
	run(b, setupTrivialNoAllocTest)
}
func BenchmarkTrivial(b *testing.B) {
	run(b, setupTrivialTest)
}

func BenchmarkBlockingChannel(b *testing.B) {
	run(b, setupBlockingChannelTest)
}

func BenchmarkNonblockingChannel(b *testing.B) {
	run(b, setupNonblockingChannelTest)
}

func BenchmarkDoubleChannel(b *testing.B) {
	run(b, setupDoubleChannelTest)
}

func BenchmarkUDP(b *testing.B) {
	run(b, setupUDPTest)
}

func BenchmarkBatchTCP(b *testing.B) {
	run(b, setupBatchTCPTest)
}

func BenchmarkWireGuardTest(b *testing.B) {
	b.Skip("https://github.com/tailscale/tailscale/issues/2716")
	run(b, func(logf logger.Logf, traf *TrafficGen) {
		setupWGTest(b, logf, traf, Addr1, Addr2)
	})
}

type SetupFunc func(logger.Logf, *TrafficGen)

func run(b *testing.B, setup SetupFunc) {
	sizes := []int{
		ICMPMinSize + 8,
		ICMPMinSize + 100,
		ICMPMinSize + 1000,
	}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			runOnce(b, setup, size)
		})
	}
}

func runOnce(b *testing.B, setup SetupFunc, payload int) {
	b.StopTimer()
	b.ReportAllocs()

	var logf logger.Logf = b.Logf
	if !testing.Verbose() {
		logf = logger.Discard
	}

	traf := NewTrafficGen(b.StartTimer)
	setup(logf, traf)

	logf("initialized. (n=%v)", b.N)
	b.SetBytes(int64(payload))

	traf.Start(Addr1.Addr(), Addr2.Addr(), payload, int64(b.N))

	var cur, prev Snapshot
	var pps int64
	i := 0
	for traf.Running() {
		i += 1
		time.Sleep(10 * time.Millisecond)

		if (i % 100) == 0 {
			prev = cur
			cur = traf.Snap()
			d := cur.Sub(prev)

			if prev.WhenNsec != 0 {
				logf("%v @%7d pkt/sec", d, pps)
			}
		}

		pps = traf.Adjust()
	}

	cur = traf.Snap()
	d := cur.Sub(prev)
	loss := float64(d.LostPackets) / float64(d.RxPackets)

	b.ReportMetric(loss*100, "%lost")
}
