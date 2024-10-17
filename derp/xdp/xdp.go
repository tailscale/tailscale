// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package xdp contains the XDP STUN program.
package xdp

// XDPAttachFlags represents how XDP program will be attached to interface. This
// is a mirror of cilium/ebpf/link.AttachFlags, without pulling it in for
// non-Linux.
type XDPAttachFlags uint32

const (
	// XDPDriverFallbackGenericMode attempts XDPDriverMode, and falls back to
	// XDPGenericMode if the driver does not support XDP.
	XDPDriverFallbackGenericMode = 0
)

const (
	// XDPGenericMode (SKB) links XDP BPF program for drivers which do
	// not yet support native XDP.
	XDPGenericMode XDPAttachFlags = 1 << (iota + 1)
	// XDPDriverMode links XDP BPF program into the driver’s receive path.
	XDPDriverMode
	// XDPOffloadMode offloads the entire XDP BPF program into hardware.
	XDPOffloadMode
)

// STUNServerConfig represents the configuration of a STUNServer.
type STUNServerConfig struct {
	DeviceName  string
	DstPort     int
	AttachFlags XDPAttachFlags
	// Return XDP verifier errors in their entirety. This is a multiline error
	// that can be very long. Full verifier errors are primarily useful during
	// development, but should be mostly unexpected in a production environment.
	FullVerifierErr bool
}

type STUNServerOption interface {
	apply(*stunServerOptions)
}

type stunServerOptions struct {
	//lint:ignore U1000 used in xdp_linux_test.go
	noAttach bool
}
