// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package netbench is a minimal iperf-like network benchmarking toolkit,
// served over HTTP by test agents on VMs that have no benchmarking tools
// of their own (natlab's tta, and the tswgbench agent). It's for comparing
// data planes, such as the tswg kernel module and wireguard-go; see
// https://github.com/tailscale/tailscale/issues/426.
//
// The server side (Register) is Linux only, since it reads CPU use from
// /proc/stat. The client side (RunSuite) runs anywhere.
package netbench

// Stats are the benchmark server's cumulative counters.
type Stats struct {
	TCPBytes     int64 // received by the TCP sink
	TCPSentBytes int64 // sent in responses to fetches; see RunTCPFetch
	UDPPackets   int64
	UDPBytes     int64
}

// CPU is a snapshot of the node's CPU time, in USER_HZ ticks, summed over
// all CPUs.
type CPU struct {
	Busy, Total int64
	NumCPU      int
}

// Result is the result of a benchmark client run.
type Result struct {
	Bytes   int64
	Packets int64
	Seconds float64
}

// RTT is the result of an RTT run, in milliseconds.
type RTT struct {
	Samples  int
	Lost     int
	P50, P90 float64
	P99, Max float64
	Mean     float64
}
