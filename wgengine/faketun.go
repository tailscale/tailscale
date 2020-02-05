// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"github.com/tailscale/wireguard-go/tun"
	"io"
	"os"
)

type fakeTun struct {
	datachan  chan []byte
	evchan    chan tun.Event
	closechan chan struct{}
}

func NewFakeTun() tun.Device {
	return &fakeTun{
		datachan:  make(chan []byte),
		evchan:    make(chan tun.Event),
		closechan: make(chan struct{}),
	}
}

func (t *fakeTun) File() *os.File {
	panic("fakeTun.File() called, which makes no sense")
}

func (t *fakeTun) Close() error {
	close(t.closechan)
	close(t.datachan)
	return nil
}

func (t *fakeTun) InsertRead(b []byte) {
	t.datachan <- b
}

func (t *fakeTun) Read(out []byte, offset int) (int, error) {
	select {
	case <-t.closechan:
		return 0, io.EOF
	case b := <-t.datachan:
		copy(out[offset:offset+len(b)], b)
		return len(b), nil
	}
}

func (t *fakeTun) Write(b []byte, n int) (int, error) { return len(b), nil }
func (t *fakeTun) Flush() error                       { return nil }
func (t *fakeTun) MTU() (int, error)                  { return 1500, nil }
func (t *fakeTun) Name() (string, error)              { return "FakeTun", nil }
func (t *fakeTun) Events() chan tun.Event             { return t.evchan }
