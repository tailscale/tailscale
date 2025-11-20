// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package linuxdnsfight

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"
)

func TestWatchFile(t *testing.T) {
	dir := t.TempDir()
	filepath := dir + "/test.txt"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var callbackCalled atomic.Bool
	callbackDone := make(chan bool)
	callback := func() {
		// We only send to the channel once to avoid blocking if the
		// callback is called multiple times -- this happens occasionally
		// if inotify sends multiple events before we cancel the context.
		if !callbackCalled.Load() {
			callbackDone <- true
			callbackCalled.Store(true)
		}
	}

	var eg errgroup.Group
	eg.Go(func() error { return watchFile(ctx, dir, filepath, callback) })

	// Keep writing until we get a callback.
	func() {
		for i := range 10000 {
			if err := os.WriteFile(filepath, []byte(fmt.Sprintf("write%d", i)), 0644); err != nil {
				t.Fatal(err)
			}
			select {
			case <-callbackDone:
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	}()

	cancel()
	if err := eg.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		t.Error(err)
	}
	if !callbackCalled.Load() {
		t.Error("callback was not called")
	}
}
