// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest"
)

func TestWatchdog(t *testing.T) {
	t.Parallel()

	var maxWaitMultiple time.Duration = 1
	if runtime.GOOS == "darwin" {
		// Work around slow close syscalls on Big Sur with content filter Network Extensions installed.
		// See https://github.com/tailscale/tailscale/issues/1598.
		maxWaitMultiple = 15
	}

	t.Run("default watchdog does not fire", func(t *testing.T) {
		t.Parallel()
		e, err := NewFakeUserspaceEngine(t.Logf, 0)
		if err != nil {
			t.Fatal(err)
		}

		e = NewWatchdog(e)
		e.(*watchdogEngine).maxWait = maxWaitMultiple * 150 * time.Millisecond
		e.(*watchdogEngine).logf = t.Logf
		e.(*watchdogEngine).fatalf = t.Fatalf

		e.RequestStatus()
		e.RequestStatus()
		e.RequestStatus()
		e.Close()
	})

	t.Run("watchdog fires on blocked getStatus", func(t *testing.T) {
		t.Parallel()
		e, err := NewFakeUserspaceEngine(t.Logf, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(e.Close)
		usEngine := e.(*userspaceEngine)
		e = NewWatchdog(e)
		wdEngine := e.(*watchdogEngine)
		wdEngine.maxWait = maxWaitMultiple * 100 * time.Millisecond

		logBuf := new(tstest.MemLogger)
		fatalCalled := make(chan struct{})
		wdEngine.logf = logBuf.Logf
		wdEngine.fatalf = func(format string, args ...any) {
			t.Logf("FATAL: %s", fmt.Sprintf(format, args...))
			fatalCalled <- struct{}{}
		}

		usEngine.wgLock.Lock() // blocks getStatus so the watchdog will fire

		go e.RequestStatus()

		select {
		case <-fatalCalled:
			logs := logBuf.String()
			if !strings.Contains(logs, "goroutine profile: total ") {
				t.Errorf("fatal called without watchdog stacks, got: %s", logs)
			}
			re := regexp.MustCompile(`(?m)^\s*in-flight\[\d+\]: name=RequestStatus duration=.* start=.*$`)
			if !re.MatchString(logs) {
				t.Errorf("fatal called without in-flight list, got: %s", logs)
			}

			// expected
		case <-time.After(3 * time.Second):
			t.Fatalf("watchdog failed to fire")
		}

		usEngine.wgLock.Unlock()
		wdEngine.fatalf = t.Fatalf
		wdEngine.Close()
	})
}
