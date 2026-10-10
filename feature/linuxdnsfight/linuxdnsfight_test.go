// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package linuxdnsfight

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"
)

// startWatch runs watchFile on dir/filename and returns a channel that
// receives a value for each callback. It waits for the callback that
// watchFile makes at startup, so the watch is in place on return.
func startWatch(t *testing.T, dir, filename string) <-chan struct{} {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	calls := make(chan struct{}, 100)
	var eg errgroup.Group
	eg.Go(func() error {
		return watchFile(ctx, dir, filename, func() { calls <- struct{}{} })
	})
	t.Cleanup(func() {
		cancel()
		if err := eg.Wait(); err != nil && !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
	select {
	case <-calls:
	case <-time.After(5 * time.Second):
		t.Fatal("no callback at startup")
	}
	return calls
}

func TestWatchFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	calls := startWatch(t, dir, path)

	if err := os.WriteFile(path, []byte("write"), 0644); err != nil {
		t.Fatal(err)
	}
	select {
	case <-calls:
	case <-time.After(5 * time.Second):
		t.Fatal("callback was not called after write")
	}
}

func TestWatchFileIgnoresReadsAndOtherFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	calls := startWatch(t, dir, path)

	for range 100 {
		if _, err := os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "other.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	select {
	case <-calls:
		t.Fatal("callback called for reads or another file")
	case <-time.After(200 * time.Millisecond):
	}
}
