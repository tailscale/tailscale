// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_netstack

package tstun

import (
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type (
	netstack_PacketBuffer = stack.PacketBuffer
	netstack_GSO          = stack.GSO
)

const (
	netstack_GSONone   = stack.GSONone
	netstack_GSOTCPv4  = stack.GSOTCPv4
	netstack_GSOTCPv6  = stack.GSOTCPv6
	netstack_GSOGvisor = stack.GSOGvisor
)
