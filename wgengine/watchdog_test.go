// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"tailscale.com/wgengine/router"
)

func TestWatchdog(t *testing.T) {
	t.Parallel()

	t.Run("default watchdog does not fire", func(t *testing.T) {
		t.Parallel()
		tun := NewFakeTun()
		e, err := NewUserspaceEngineAdvanced(t.Logf, tun, router.NewFake, 0)
		if err != nil {
			t.Fatal(err)
		}

		e = NewWatchdog(e)
		e.(*watchdogEngine).maxWait = 150 * time.Millisecond

		e.RequestStatus()
		e.RequestStatus()
		e.RequestStatus()
		e.Close()
	})

	t.Run("watchdog fires on blocked getStatus", func(t *testing.T) {
		t.Parallel()
		tun := NewFakeTun()
		e, err := NewUserspaceEngineAdvanced(t.Logf, tun, router.NewFake, 0)
		if err != nil {
			t.Fatal(err)
		}
		usEngine := e.(*userspaceEngine)
		e = NewWatchdog(e)
		wdEngine := e.(*watchdogEngine)
		wdEngine.maxWait = 100 * time.Millisecond

		logBuf := new(bytes.Buffer)
		fatalCalled := make(chan struct{})
		wdEngine.logf = func(format string, args ...interface{}) {
			fmt.Fprintf(logBuf, format+"\n", args...)
		}
		wdEngine.fatalf = func(format string, args ...interface{}) {
			t.Logf("FATAL: %s", fmt.Sprintf(format, args...))
			fatalCalled <- struct{}{}
		}

		usEngine.wgLock.Lock() // blocks getStatus so the watchdog will fire

		go e.RequestStatus()

		select {
		case <-fatalCalled:
			if !strings.Contains(logBuf.String(), "goroutine profile: total ") {
				t.Errorf("fatal called without watchdog stacks, got: %s", logBuf.String())
			}
			// expected
		case <-time.After(3 * time.Second):
			t.Fatalf("watchdog failed to fire")
		}
	})
}
