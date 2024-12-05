// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"io"
	"os"

	"github.com/tailscale/wireguard-go/tun"
)

type fakeTUN struct {
	evchan    chan tun.Event
	closechan chan struct{}
}

// NewFake returns a tun.Device that does nothing.
func NewFake() tun.Device {
	return &fakeTUN{
		evchan:    make(chan tun.Event),
		closechan: make(chan struct{}),
	}
}

func (t *fakeTUN) File() *os.File {
	panic("fakeTUN.File() called, which makes no sense")
}

func (t *fakeTUN) Close() error {
	close(t.closechan)
	close(t.evchan)
	return nil
}

func (t *fakeTUN) Read(out [][]byte, sizes []int, offset int) (int, error) {
	<-t.closechan
	return 0, io.EOF
}

func (t *fakeTUN) Write(b [][]byte, n int) (int, error) {
	select {
	case <-t.closechan:
		return 0, ErrClosed
	default:
	}
	return 1, nil
}

// FakeTUNName is the name of the fake TUN device.
const FakeTUNName = "FakeTUN"

func (t *fakeTUN) Flush() error             { return nil }
func (t *fakeTUN) MTU() (int, error)        { return 1500, nil }
func (t *fakeTUN) Name() (string, error)    { return FakeTUNName, nil }
func (t *fakeTUN) Events() <-chan tun.Event { return t.evchan }
func (t *fakeTUN) BatchSize() int           { return 1 }
func (t *fakeTUN) IsFakeTun() bool          { return true }
