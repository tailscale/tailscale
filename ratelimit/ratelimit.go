// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ratelimit

import (
	"sync"
	"time"

	"tailscale.com/types/structs"
)

type Bucket struct {
	_            structs.Incomparable
	mu           sync.Mutex
	FillInterval time.Duration
	Burst        int
	v            int
	quitCh       chan struct{}
	started      bool
	closed       bool
}

func (b *Bucket) startLocked() {
	b.v = b.Burst
	b.quitCh = make(chan struct{})
	b.started = true

	t := time.NewTicker(b.FillInterval)
	go func() {
		for {
			select {
			case <-b.quitCh:
				return
			case <-t.C:
				b.tick()
			}
		}
	}()
}

func (b *Bucket) tick() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.v < b.Burst {
		b.v++
	}
}

func (b *Bucket) Close() {
	b.mu.Lock()
	if !b.started {
		b.closed = true
		b.mu.Unlock()
		return
	}
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	b.mu.Unlock()

	b.quitCh <- struct{}{}
}

func (b *Bucket) TryGet() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.started {
		b.startLocked()
	}
	if b.v > 0 {
		b.v--
		return b.v + 1
	}
	return 0
}
