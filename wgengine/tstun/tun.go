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
	"sync/atomic"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/packet"
)

const readMaxSize = device.MaxMessageSize

// MaxPacketSize is the maximum size (in bytes)
// of a packet that can be injected into a tstun.TUN.
const MaxPacketSize = device.MaxContentSize

// PacketStartOffset is the amount of scrap space that must exist
// before &packet[offset] in a packet passed to Read, Write, or InjectInbound.
// This is necessary to avoid reallocation in wireguard-go internals.
const PacketStartOffset = device.MessageTransportHeaderSize

var (
	ErrClosed       = errors.New("device closed")
	ErrFiltered     = errors.New("packet dropped by filter")
	ErrPacketTooBig = errors.New("packet too big")
)

// FilterFunc is a packet-filtering function with access to the TUN device.
type FilterFunc func(*packet.QDecode, *TUN) filter.Response

// TUN wraps a tun.Device from wireguard-go,
// augmenting it with filtering and packet injection.
// All the added work happens in Read and Write:
// the other methods delegate to the underlying tdev.
type TUN struct {
	logf logger.Logf
	// tdev is the underlying TUN device.
	tdev tun.Device

	// buffer stores the oldest unconsumed packet from tdev.
	// It is made a static buffer in order to avoid graticious allocation.
	buffer [readMaxSize]byte
	// bufferConsumed synchronizes access to buffer (shared by Read and poll).
	bufferConsumed chan struct{}

	// closed signals poll (by closing) when the device is closed.
	closed chan struct{}
	// errors is the error queue populated by poll.
	errors chan error
	// outbound is the queue by which packets leave the TUN device.
	// The directions are relative to the network, not the device:
	// inbound packets arrive via UDP and are written into the TUN device;
	// outbound packets are read from the TUN device and sent out via UDP.
	// This queue is needed because although inbound writes are synchronous,
	// the other direction must wait on a Wireguard goroutine to poll it.
	outbound chan []byte

	// filter is the main packet filter set based on common rules and ACLs.
	// Unlike pre-/post-filters, it is updated at runtime by the control client.
	filter atomic.Value // of *filter.Filter
	// filterFlags control the verbosity of logging packet drops/accepts.
	filterFlags filter.RunFlags

	// The following are exported, but not synchronized in any way.
	// The intent is for them to be initialized once and not touched afterward.

	// PreFilterIn are the inbound filter functions that run before the main filter
	// and therefore see the packets that are later dropped by it.
	PreFilterIn []FilterFunc
	// PostFilterIn are the inbound filter functions that run after the main filter.
	PostFilterIn []FilterFunc

	// PreFilterOut are the outbound filter functions that run before the main filter
	// and therefore see the packets that are later dropped by it.
	PreFilterOut []FilterFunc
	// PostFilterOut are the outbound filter functions that run after the main filter.
	PostFilterOut []FilterFunc
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
		filterFlags:    filter.LogAccepts | filter.LogDrops,
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

		// Read may use memory in t.buffer before PacketStartOffset for mandatory headers.
		// This is the rationale behind the tun.TUN.{Read,Write} interfaces
		// and the reason t.buffer has size MaxMessageSize and not MaxContentSize.
		n, err := t.tdev.Read(t.buffer[:], PacketStartOffset)
		if err != nil {
			select {
			case <-t.closed:
				return
			case t.errors <- err:
				// In principle, read errors are not fatal (but wireguard-go disagrees).
				t.bufferConsumed <- struct{}{}
			}
		} else {
			select {
			case <-t.closed:
				return
			case t.outbound <- t.buffer[PacketStartOffset : PacketStartOffset+n]:
				// continue
			}
		}
	}
}

func (t *TUN) filterOut(buf []byte) filter.Response {
	var q packet.QDecode
	q.Decode(buf)

	for _, filterFunc := range t.PreFilterOut {
		if filterFunc(&q, t) == filter.Drop {
			return filter.Drop
		}
	}

	filt, _ := t.filter.Load().(*filter.Filter)

	if filt == nil {
		t.logf("Warning: you forgot to use SetFilter()! Packet dropped.")
		return filter.Drop
	}

	if filt.RunOut(buf, &q, t.filterFlags) != filter.Accept {
		return filter.Drop
	}

	for _, filterFunc := range t.PostFilterOut {
		if filterFunc(&q, t) == filter.Drop {
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
		if &packet[0] == &t.buffer[PacketStartOffset] {
			t.bufferConsumed <- struct{}{}
		}
	}

	response := t.filterOut(buf[offset : offset+n])
	if response != filter.Accept {
		// Wireguard considers read errors fatal; pretend nothing was read
		return 0, nil
	}

	return n, nil
}

func (t *TUN) filterIn(buf []byte) filter.Response {
	var q packet.QDecode
	q.Decode(buf)

	for _, filterFunc := range t.PreFilterIn {
		if filterFunc(&q, t) == filter.Drop {
			return filter.Drop
		}
	}

	filt, _ := t.filter.Load().(*filter.Filter)

	if filt == nil {
		t.logf("Warning: you forgot to use SetFilter()! Packet dropped.")
		return filter.Drop
	}

	if filt.RunIn(buf, &q, t.filterFlags) != filter.Accept {
		return filter.Drop
	}

	for _, filterFunc := range t.PostFilterIn {
		if filterFunc(&q, t) == filter.Drop {
			return filter.Drop
		}
	}

	return filter.Accept
}

func (t *TUN) Write(buf []byte, offset int) (int, error) {
	response := t.filterIn(buf[offset:])
	if response != filter.Accept {
		return 0, ErrFiltered
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
// The data in the packet should start at the given offset.
// There must be enough space before offset to fit PacketStartOffset bytes.
// The leading space is used by Wireguard internally to avoid reallocation.
// This parameter is required to ensure callers remember to reserve space.
func (t *TUN) InjectInbound(packet []byte, offset int) error {
	if len(packet) > MaxPacketSize {
		return ErrPacketTooBig
	}
	// We write to the underlying device directly to bypass inbound filters.
	_, err := t.tdev.Write(packet, offset)
	return err
}

// InjectOutbound makes the TUN device behave as if a packet
// with the given contents was sent to the network.
// It does not block, but takes ownership of the packet.
func (t *TUN) InjectOutbound(packet []byte) error {
	if len(packet) > MaxPacketSize {
		return ErrPacketTooBig
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
