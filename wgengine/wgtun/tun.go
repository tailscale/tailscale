// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgtun

import (
	"errors"
	"os"
	"sync"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
)

const MaxPacketSize = device.MaxContentSize

var (
	ErrFiltered     = errors.New("packet dropped by filter")
	ErrPacketTooBig = errors.New("packet too big")
)

// Device wraps a tun.Device from wireguard-go,
// augmenting it with filtering and packet injection.
// All the added work happens in Read and Write:
// the other methods delegate to the underlying innerDevice.
type Device struct {
	innerDevice tun.Device

	// Inbound packets can be written directly into the TUN device,
	// but the other direction must wait on Wireguard to poll it.
	// The packets are kept in the queue while waiting.
	outbound chan []byte

	// Filters are updated by ipn/local during the netmap refresh.
	// They may be in use when this happens, hence the need for locking.
	filterLock sync.Mutex
	filterIn   func(b []byte) filter.Response
	filterOut  func(b []byte) filter.Response
}

func WrapTun(logf logger.Logf, device tun.Device) *Device {
	nofilter := func(b []byte) filter.Response {
		// for safety, default to dropping all packets
		logf("Warning: you forgot to use tundev.SetFilterInOut()! Packet dropped.")
		return filter.Drop
	}

	return &Device{
		innerDevice: device,
		outbound:    make(chan []byte),
		filterIn:    nofilter,
		filterOut:   nofilter,
	}
}

func (d *Device) Close() error {
	return d.innerDevice.Close()
}

func (d *Device) Events() chan tun.Event {
	return d.innerDevice.Events()
}

func (d *Device) File() *os.File {
	return d.innerDevice.File()
}

func (d *Device) Flush() error {
	return d.innerDevice.Flush()
}

func (d *Device) MTU() (int, error) {
	return d.innerDevice.MTU()
}

func (d *Device) Name() (string, error) {
	return d.innerDevice.Name()
}

func (d *Device) Read(buf []byte, offset int) (n int, err error) {
	select {
	case packet := <-d.outbound:
		n = copy(buf[offset:], packet)
	default:
		n, err = d.innerDevice.Read(buf, offset)
	}

	d.filterLock.Lock()
	filterFunc := d.filterOut
	d.filterLock.Unlock()

	if err == nil && filterFunc != nil {
		response := filterFunc(buf[offset : offset+n])
		if response != filter.Accept {
			// Wireguard considers read errors fatal; pretend nothing was read
			n = 0
		}
	}

	return n, err
}

func (d *Device) Write(buf []byte, offset int) (int, error) {
	d.filterLock.Lock()
	filterFunc := d.filterIn
	d.filterLock.Unlock()

	if filterFunc != nil {
		response := filterFunc(buf[offset:])
		if response != filter.Accept {
			return 0, ErrFiltered
		}
	}

	return d.innerDevice.Write(buf, offset)
}

func (d *Device) SetFilterInOut(in, out func(b []byte) filter.Response) {
	d.filterLock.Lock()
	d.filterIn = in
	d.filterOut = out
	d.filterLock.Unlock()
}

func (d *Device) InjectInbound(packet []byte) error {
	if len(packet) > MaxPacketSize {
		return ErrPacketTooBig
	}
	_, err := d.Write(packet, 0)
	return err
}

func (d *Device) InjectOutbound(packet []byte) error {
	if len(packet) > MaxPacketSize {
		return ErrPacketTooBig
	}
	d.outbound <- packet
	return nil
}

func (d *Device) Unwrap() tun.Device {
	return d.innerDevice
}
