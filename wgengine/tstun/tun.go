// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tstun provides a TUN struct implementing the tun.Device interface
// with additional features as required by wgengine.
package tstun

import (
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/packet"
)

const (
	readMaxSize = device.MaxMessageSize
	readOffset  = device.MessageTransportHeaderSize
)

// PacketStartOffset is the minimal amount of leading space that must exist
// before &packet[offset] in a packet passed to Read, Write, or InjectInboundDirect.
// This is necessary to avoid reallocation in wireguard-go internals.
const PacketStartOffset = device.MessageTransportHeaderSize

// MaxPacketSize is the maximum size (in bytes)
// of a packet that can be injected into a tstun.TUN.
const MaxPacketSize = device.MaxContentSize

var (
	// ErrClosed is returned when attempting an operation on a closed TUN.
	ErrClosed = errors.New("device closed")
	// ErrFiltered is returned when the acted-on packet is rejected by a filter.
	ErrFiltered = errors.New("packet dropped by filter")
)

var (
	errPacketTooBig = errors.New("packet too big")
	errOffsetTooBig = errors.New("offset larger than buffer length")
)

// FilterFunc is a packet-filtering function with access to the TUN device.
type FilterFunc func(*packet.ParsedPacket, *TUN) filter.Response

// TUN wraps a tun.Device from wireguard-go,
// augmenting it with filtering and packet injection.
// All the added work happens in Read and Write:
// the other methods delegate to the underlying tdev.
type TUN struct {
	logf logger.Logf
	// tdev is the underlying TUN device.
	tdev tun.Device

	// buffer stores the oldest unconsumed packet from tdev.
	// It is made a static buffer in order to avoid allocations.
	buffer [readMaxSize]byte
	// bufferConsumed synchronizes access to buffer (shared by Read and poll).
	bufferConsumed chan struct{}
	// parsedPacketPool holds a pool of ParsedPacket structs for use in filtering.
	// This is needed because escape analysis cannot see that parsed packets
	// do not escape through {Pre,Post}Filter{In,Out}.
	parsedPacketPool sync.Pool // of *packet.ParsedPacket

	// closed signals poll (by closing) when the device is closed.
	closed chan struct{}
	// errors is the error queue populated by poll.
	errors chan error
	// outbound is the queue by which packets leave the TUN device.
	//
	// The directions are relative to the network, not the device:
	// inbound packets arrive via UDP and are written into the TUN device;
	// outbound packets are read from the TUN device and sent out via UDP.
	// This queue is needed because although inbound writes are synchronous,
	// the other direction must wait on a Wireguard goroutine to poll it.
	//
	// Empty reads are skipped by Wireguard, so it is always legal
	// to discard an empty packet instead of sending it through t.outbound.
	outbound chan []byte

	// fitler stores the currently active package filter
	filter atomic.Value // of *filter.Filter
	// filterFlags control the verbosity of logging packet drops/accepts.
	filterFlags filter.RunFlags

	// PreFilterIn is the inbound filter function that runs before the main filter
	// and therefore sees the packets that may be later dropped by it.
	PreFilterIn FilterFunc
	// PostFilterIn is the inbound filter function that runs after the main filter.
	PostFilterIn FilterFunc
	// PreFilterOut is the outbound filter function that runs before the main filter
	// and therefore sees the packets that may be later dropped by it.
	PreFilterOut FilterFunc
	// PostFilterOut is the outbound filter function that runs after the main filter.
	PostFilterOut FilterFunc

	// disableFilter disables all filtering when set. This should only be used in tests.
	disableFilter bool
}

func WrapTUN(logf logger.Logf, tdev tun.Device) *TUN {
	tun := &TUN{
		logf: logf,
		tdev: tdev,
		// bufferConsumed is conceptually a condition variable:
		// a goroutine should not block when setting it, even with no listeners.
		bufferConsumed: make(chan struct{}, 1),
		closed:         make(chan struct{}),
		errors:         make(chan error),
		outbound:       make(chan []byte),
		// TODO(dmytro): (highly rate-limited) hexdumps should happen on unknown packets.
		filterFlags: filter.LogAccepts | filter.LogDrops,
	}

	tun.parsedPacketPool.New = func() interface{} {
		return new(packet.ParsedPacket)
	}

	go tun.poll()
	// The buffer starts out consumed.
	tun.bufferConsumed <- struct{}{}

	return tun
}

func (t *TUN) Close() error {
	select {
	case <-t.closed:
		// continue
	default:
		// Other channels need not be closed: poll will exit gracefully after this.
		close(t.closed)
	}

	return t.tdev.Close()
}

func (t *TUN) Events() chan tun.Event {
	return t.tdev.Events()
}

func (t *TUN) File() *os.File {
	return t.tdev.File()
}

func (t *TUN) Flush() error {
	return t.tdev.Flush()
}

func (t *TUN) MTU() (int, error) {
	return t.tdev.MTU()
}

func (t *TUN) Name() (string, error) {
	return t.tdev.Name()
}

// poll polls t.tdev.Read, placing the oldest unconsumed packet into t.buffer.
// This is needed because t.tdev.Read in general may block (it does on Windows),
// so packets may be stuck in t.outbound if t.Read called t.tdev.Read directly.
func (t *TUN) poll() {
	for {
		select {
		case <-t.closed:
			return
		case <-t.bufferConsumed:
			// continue
		}

		// Read may use memory in t.buffer before readOffset for mandatory headers.
		// This is the rationale behind the tun.TUN.{Read,Write} interfaces
		// and the reason t.buffer has size MaxMessageSize and not MaxContentSize.
		n, err := t.tdev.Read(t.buffer[:], readOffset)
		if err != nil {
			select {
			case <-t.closed:
				return
			case t.errors <- err:
				// In principle, read errors are not fatal (but wireguard-go disagrees).
				t.bufferConsumed <- struct{}{}
			}
			continue
		}

		// Wireguard will skip an empty read,
		// so we might as well do it here to avoid the send through t.outbound.
		if n == 0 {
			t.bufferConsumed <- struct{}{}
			continue
		}

		select {
		case <-t.closed:
			return
		case t.outbound <- t.buffer[readOffset : readOffset+n]:
			// continue
		}
	}
}

func (t *TUN) filterOut(buf []byte) filter.Response {
	p := t.parsedPacketPool.Get().(*packet.ParsedPacket)
	p.Decode(buf)

	if t.PreFilterOut != nil {
		if t.PreFilterOut(p, t) == filter.Drop {
			return filter.Drop
		}
	}

	filt, _ := t.filter.Load().(*filter.Filter)

	if filt == nil {
		t.logf("tstun: warning: you forgot to use SetFilter()! Packet dropped.")
		return filter.Drop
	}

	if filt.RunOut(p, t.filterFlags) != filter.Accept {
		return filter.Drop
	}

	if t.PostFilterOut != nil {
		if t.PostFilterOut(p, t) == filter.Drop {
			return filter.Drop
		}
	}

	return filter.Accept
}

func (t *TUN) Read(buf []byte, offset int) (int, error) {
	var n int

	select {
	case <-t.closed:
		return 0, io.EOF
	case err := <-t.errors:
		return 0, err
	case packet := <-t.outbound:
		n = copy(buf[offset:], packet)
		// t.buffer has a fixed location in memory,
		// so this is the easiest way to tell when it has been consumed.
		// &packet[0] can be used because empty packets do not reach t.outbound.
		if &packet[0] == &t.buffer[readOffset] {
			t.bufferConsumed <- struct{}{}
		}
	}

	if !t.disableFilter {
		response := t.filterOut(buf[offset : offset+n])
		if response != filter.Accept {
			// Wireguard considers read errors fatal; pretend nothing was read
			return 0, nil
		}
	}

	return n, nil
}

func (t *TUN) filterIn(buf []byte) filter.Response {
	p := t.parsedPacketPool.Get().(*packet.ParsedPacket)
	p.Decode(buf)

	if t.PreFilterIn != nil {
		if t.PreFilterIn(p, t) == filter.Drop {
			return filter.Drop
		}
	}

	filt, _ := t.filter.Load().(*filter.Filter)

	if filt == nil {
		t.logf("tstun: warning: you forgot to use SetFilter()! Packet dropped.")
		return filter.Drop
	}

	if filt.RunIn(p, t.filterFlags) != filter.Accept {
		return filter.Drop
	}

	if t.PostFilterIn != nil {
		if t.PostFilterIn(p, t) == filter.Drop {
			return filter.Drop
		}
	}

	return filter.Accept
}

func (t *TUN) Write(buf []byte, offset int) (int, error) {
	if !t.disableFilter {
		response := t.filterIn(buf[offset:])
		if response != filter.Accept {
			return 0, ErrFiltered
		}
	}

	return t.tdev.Write(buf, offset)
}

func (t *TUN) GetFilter() *filter.Filter {
	filt, _ := t.filter.Load().(*filter.Filter)
	return filt
}

func (t *TUN) SetFilter(filt *filter.Filter) {
	t.filter.Store(filt)
}

// InjectInbound makes the TUN device behave as if a packet
// with the given contents was received from the network.
// It blocks and does not take ownership of the packet.
//
// The packet contents are to start at &buf[offset].
// If the underlying TUN device is real,
// offset must be greater or equal to PacketStartOffset.
// The space before &buf[offset] will be used by Wireguard.
func (t *TUN) InjectInboundDirect(buf []byte, offset int) error {
	if len(buf) > MaxPacketSize {
		return errPacketTooBig
	}
	if len(buf) < offset {
		return errOffsetTooBig
	}

	_, err := t.Write(buf, offset)
	return err
}

// InjectInboundCopy takes a packet without leading space,
// reallocates in to conform to the InjectInbondDirect interface
// and calls InjectInbondDirect on it. Injecting a nil packet is a no-op.
func (t *TUN) InjectInboundCopy(packet []byte) error {
	// We duplicate this check from InjectInboundDirect here
	// to avoid wasting an allocation on an oversized packet.
	if len(packet) > MaxPacketSize {
		return errPacketTooBig
	}
	if len(packet) == 0 {
		return nil
	}

	buf := make([]byte, PacketStartOffset+len(packet))
	copy(buf[PacketStartOffset:], packet)

	return t.InjectInboundDirect(buf, PacketStartOffset)
}

// InjectOutbound makes the TUN device behave as if a packet
// with the given contents was sent to the network.
// It does not block, but takes ownership of the packet.
// Injecting an empty packet is a no-op.
func (t *TUN) InjectOutbound(packet []byte) error {
	if len(packet) > MaxPacketSize {
		return errPacketTooBig
	}
	if len(packet) == 0 {
		return nil
	}
	select {
	case <-t.closed:
		return ErrClosed
	case t.outbound <- packet:
		return nil
	}
}

// Unwrap returns the underlying TUN device.
func (t *TUN) Unwrap() tun.Device {
	return t.tdev
}
