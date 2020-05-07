// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package wgtun provides a Device implementing the tun.Device interface
// with additional features as required by wgengine.
package wgtun

import (
	"errors"
	"io"
	"os"
	"sync"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
)

const (
	readMaxSize   = device.MaxMessageSize
	readOffset    = device.MessageTransportHeaderSize
	MaxPacketSize = device.MaxContentSize
)

var (
	ErrFiltered     = errors.New("packet dropped by filter")
	ErrPacketTooBig = errors.New("packet too big")
)

// Device wraps a tun.Device from wireguard-go,
// augmenting it with filtering and packet injection.
// All the added work happens in Read and Write:
// the other methods delegate to the underlying tdev.
type Device struct {
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

	// filterMu locks the filters, since they may be in use
	// during the netmap refresh when ipn/local updates them.
	filterMu sync.Mutex
	// filterIn inspects every inbound packet and accepts or drops it.
	filterIn func(b []byte) filter.Response
	// filterOut inspects every outbound packet and accepts or drops it.
	filterOut func(b []byte) filter.Response
}

func WrapTUN(logf logger.Logf, tdev tun.Device) *Device {
	nofilter := func(b []byte) filter.Response {
		// For safety, default to dropping all packets.
		logf("Warning: you forgot to use tundev.SetFilterInOut()! Packet dropped.")
		return filter.Drop
	}

	device := &Device{
		tdev:           tdev,
		bufferConsumed: make(chan struct{}),
		closed:         make(chan struct{}),
		errors:         make(chan error),
		outbound:       make(chan []byte),
		filterIn:       nofilter,
		filterOut:      nofilter,
	}
	go device.poll()
	// The buffer starts out consumed.
	device.bufferConsumed <- struct{}{}

	return device
}

func (d *Device) Close() error {
	// Other channels need not be closed: poll will exit gracefully after this.
	close(d.closed)
	return d.tdev.Close()
}

func (d *Device) Events() chan tun.Event {
	return d.tdev.Events()
}

func (d *Device) File() *os.File {
	return d.tdev.File()
}

func (d *Device) Flush() error {
	return d.tdev.Flush()
}

func (d *Device) MTU() (int, error) {
	return d.tdev.MTU()
}

func (d *Device) Name() (string, error) {
	return d.tdev.Name()
}

// poll polls d.tdev.Read, placing the oldest unconsumed packet into d.buffer.
// This is needed because d.tdev.Read in general may block (it does on Windows),
// so packets may be stuck in d.outbound if d.Read called d.tdev.Read directly.
func (d *Device) poll() {
	for {
		select {
		case <-d.closed:
			return
		case <-d.bufferConsumed:
			// continue
		}

		// Read may use memory in d.buffer before readOffset for mandatory headers.
		// This is the rationale behind the tun.Device.{Read,Write} interfaces
		// and the reason d.buffer has size MaxMessageSize and not MaxContentSize.
		n, err := d.tdev.Read(d.buffer[:], readOffset)
		if err != nil {
			d.errors <- err
			// In principle, read errors are not fatal (but wiregaurd-go disagrees).
			d.bufferConsumed <- struct{}{}
		} else {
			d.outbound <- d.buffer[readOffset : readOffset+n]
		}
	}
}

func (d *Device) Read(buf []byte, offset int) (int, error) {
	var n int

	select {
	case <-d.closed:
		return 0, io.EOF
	case err := <-d.errors:
		return 0, err
	case packet := <-d.outbound:
		n = copy(buf[offset:], packet)
		// d.buffer has a fixed location in memory,
		// so this is the easiest way to tell when it has been consumed.
		if &packet[0] == &d.buffer[readOffset] {
			d.bufferConsumed <- struct{}{}
		}
	}

	d.filterMu.Lock()
	filterFunc := d.filterOut
	d.filterMu.Unlock()

	if filterFunc != nil {
		response := filterFunc(buf[offset : offset+n])
		if response != filter.Accept {
			// Wireguard considers read errors fatal; pretend nothing was read
			n = 0
		}
	}

	return n, nil
}

func (d *Device) Write(buf []byte, offset int) (int, error) {
	d.filterMu.Lock()
	filterFunc := d.filterIn
	d.filterMu.Unlock()

	if filterFunc != nil {
		response := filterFunc(buf[offset:])
		if response != filter.Accept {
			return 0, ErrFiltered
		}
	}

	return d.tdev.Write(buf, offset)
}

// SetFilterInOut sets the in and out filters on the TUN device.
func (d *Device) SetFilterInOut(in, out func(b []byte) filter.Response) {
	d.filterMu.Lock()
	d.filterIn = in
	d.filterOut = out
	d.filterMu.Unlock()
}

// InjectInbound makes the TUN device behave as if a packet
// with the given contents was received from the network.
// It blocks and does not take ownership of the packet.
func (d *Device) InjectInbound(packet []byte) error {
	if len(packet) > MaxPacketSize {
		return ErrPacketTooBig
	}
	_, err := d.Write(packet, 0)
	return err
}

// InjectOutbound makes the TUN device behave as if a packet
// with the given contents was sent to the network.
// It does not block, but takes ownership of the packet.
func (d *Device) InjectOutbound(packet []byte) error {
	if len(packet) > MaxPacketSize {
		return ErrPacketTooBig
	}
	d.outbound <- packet
	return nil
}

func (d *Device) Unwrap() tun.Device {
	return d.tdev
}
