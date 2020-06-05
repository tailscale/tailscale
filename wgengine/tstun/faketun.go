// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tstun

import (
	"io"
	"os"

	"github.com/tailscale/wireguard-go/tun"
)

type FakeTUN struct {
	datachan  chan []byte
	evchan    chan tun.Event
	closechan chan struct{}
}

// NewFakeTUN returns a fake TUN device that does not depend on the
// operating system or any special permissions.
// It primarily exists for testing.
func NewFakeTUN() tun.Device {
	return &FakeTUN{
		datachan:  make(chan []byte),
		evchan:    make(chan tun.Event),
		closechan: make(chan struct{}),
	}
}

func (t *FakeTUN) File() *os.File {
	panic("fakeTUN.File() called, which makes no sense")
}

func (t *FakeTUN) Close() error {
	close(t.closechan)
	close(t.evchan)
	return nil
}

func (t *FakeTUN) Read(out []byte, offset int) (int, error) {
	select {
	case <-t.closechan:
		return 0, io.EOF
	case b := <-t.datachan:
		copy(out[offset:offset+len(b)], b)
		return len(b), nil
	}
}

func (t *FakeTUN) Write(b []byte, n int) (int, error) {
	select {
	case <-t.closechan:
		return 0, ErrClosed
	case t.datachan <- b[n:]:
		return len(b), nil
	}
}

func (t *FakeTUN) Flush() error           { return nil }
func (t *FakeTUN) MTU() (int, error)      { return 1500, nil }
func (t *FakeTUN) Name() (string, error)  { return "FakeTUN", nil }
func (t *FakeTUN) Events() chan tun.Event { return t.evchan }
