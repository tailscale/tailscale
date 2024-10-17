// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ios

package netstack

import (
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const (
	// tcp{RX,TX}Buf{Min,Def,Max}Size mirror gVisor defaults. We leave these
	// unchanged on iOS for now as to not increase pressure towards the
	// NetworkExtension memory limit.
	// TODO(jwhited): test memory/throughput impact of collapsing to values in _default.go
	tcpRXBufMinSize = tcp.MinBufferSize
	tcpRXBufDefSize = tcp.DefaultSendBufferSize
	tcpRXBufMaxSize = tcp.MaxBufferSize

	tcpTXBufMinSize = tcp.MinBufferSize
	tcpTXBufDefSize = tcp.DefaultReceiveBufferSize
	tcpTXBufMaxSize = tcp.MaxBufferSize
)
