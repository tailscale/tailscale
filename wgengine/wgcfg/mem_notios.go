// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios

package wgcfg

import (
	"runtime"

	"github.com/tailscale/wireguard-go/device"
)

func getDeviceOptions() []device.Option {
	// wireguard-go is a packet pipeline:
	//
	// TUN read -> encrypt -> ordered network write
	// network read -> decrypt -> ordered TUN write
	//
	// The queues that we are sizing in this function sit between head I/O
	// goroutines and downstream functions. They are buffered channels.
	//
	// The head I/O ops tend to "run ahead" the downstream functions, especially
	// when head I/O ops utilize segmentation offloading, where a single head I/O
	// op can contain about 45 packets at a typical MTU, which is equivalent to
	// 45 crypto ops.
	//
	// Small queues park I/O goroutines and hurt throughput; large queues allow
	// more packet batches and their associated memory to remain outstanding. We
	// have to find a balance. Crypto goroutines are sized to [runtime.NumCPU]
	// in wireguard-go, so we start there, and apply a benchmark-backed scaling
	// factor to reduce head I/O goroutines parking around bursts.
	const cpuScalingFactor = 4
	// maxQueueSize was the previous static default, prior to creation of the
	// [device.Option].
	const maxQueueSize = 1024
	return []device.Option{
		device.WithQueueInboundSize(min(maxQueueSize, runtime.NumCPU()*cpuScalingFactor)),
		device.WithQueueOutboundSize(min(maxQueueSize, runtime.NumCPU()*cpuScalingFactor)),
	}
}
