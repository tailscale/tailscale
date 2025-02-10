// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package packet

import (
	"io"
	"net/netip"
	"time"
)

// Callback describes a function which is called to
// record packets when debugging packet-capture.
// Such callbacks must not take ownership of the
// provided data slice: it may only copy out of it
// within the lifetime of the function.
type CaptureCallback func(CapturePath, time.Time, []byte, CaptureMeta)

// CaptureSink is the minimal interface from [tailscale.com/feature/capture]'s
// Sink type that is needed by the core (magicsock/LocalBackend/wgengine/etc).
// This lets the relativel heavy feature/capture package be optionally linked.
type CaptureSink interface {
	// Close closes
	Close() error

	// NumOutputs returns the number of outputs registered with the sink.
	NumOutputs() int

	// CaptureCallback returns a callback which can be used to
	// write packets to the sink.
	CaptureCallback() CaptureCallback

	// WaitCh returns a channel which blocks until
	// the sink is closed.
	WaitCh() <-chan struct{}

	// RegisterOutput connects an output to this sink, which
	// will be written to with a pcap stream as packets are logged.
	// A function is returned which unregisters the output when
	// called.
	//
	// If w implements io.Closer, it will be closed upon error
	// or when the sink is closed. If w implements http.Flusher,
	// it will be flushed periodically.
	RegisterOutput(w io.Writer) (unregister func())
}

// CaptureMeta contains metadata that is used when debugging.
type CaptureMeta struct {
	DidSNAT     bool           // SNAT was performed & the address was updated.
	OriginalSrc netip.AddrPort // The source address before SNAT was performed.
	DidDNAT     bool           // DNAT was performed & the address was updated.
	OriginalDst netip.AddrPort // The destination address before DNAT was performed.
}

// CapturePath describes where in the data path the packet was captured.
type CapturePath uint8

// CapturePath values
const (
	// FromLocal indicates the packet was logged as it traversed the FromLocal path:
	// i.e.: A packet from the local system into the TUN.
	FromLocal CapturePath = 0
	// FromPeer indicates the packet was logged upon reception from a remote peer.
	FromPeer CapturePath = 1
	// SynthesizedToLocal indicates the packet was generated from within tailscaled,
	// and is being routed to the local machine's network stack.
	SynthesizedToLocal CapturePath = 2
	// SynthesizedToPeer indicates the packet was generated from within tailscaled,
	// and is being routed to a remote Wireguard peer.
	SynthesizedToPeer CapturePath = 3

	// PathDisco indicates the packet is information about a disco frame.
	PathDisco CapturePath = 254
)
