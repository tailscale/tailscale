// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import "sync"

// LocalBackendFuture is a Future that returns a *LocalBackend.
type LocalBackendFuture struct {
	getOnce sync.Once
	ch      chan *LocalBackend
	v       *LocalBackend
}

func (f *LocalBackendFuture) Get() *LocalBackend {
	f.getOnce.Do(f.get)
	return f.v
}

func (f *LocalBackendFuture) get()                { f.v = <-f.ch }
func (f *LocalBackendFuture) Set(v *LocalBackend) { f.ch <- v }

func NewLocalBackendFuture() *LocalBackendFuture {
	return &LocalBackendFuture{
		ch: make(chan *LocalBackend, 1),
	}
}
