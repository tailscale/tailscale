// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"testing/synctest"

	"tailscale.com/util/eventbus"
)

func TestLinkChangeLogLimiter(t *testing.T) { synctest.Test(t, syncTestLinkChangeLogLimiter) }

func syncTestLinkChangeLogLimiter(t *testing.T) {
	bus := eventbus.New()
	defer bus.Close()
	mon, err := New(bus, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer mon.Close()

	var logBuffer bytes.Buffer
	logf := func(format string, args ...any) {
		t.Logf("captured log: "+format, args...)

		if format[len(format)-1] != '\n' {
			format += "\n"
		}
		fmt.Fprintf(&logBuffer, format, args...)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	logf = LinkChangeLogLimiter(ctx, logf, mon)

	// Log once, which should write to our log buffer.
	logf("hello %s", "world")
	if got := logBuffer.String(); got != "hello world\n" {
		t.Errorf("unexpected log buffer contents: %q", got)
	}

	// Log again, which should not write to our log buffer.
	logf("hello %s", "andrew")
	if got := logBuffer.String(); got != "hello world\n" {
		t.Errorf("unexpected log buffer contents: %q", got)
	}

	// Log a different message, which should write to our log buffer.
	logf("other message")
	if got := logBuffer.String(); got != "hello world\nother message\n" {
		t.Errorf("unexpected log buffer contents: %q", got)
	}

	// Synthesize a fake major change event, which should clear the format
	// string cache and allow the next log to write to our log buffer.
	//
	// InjectEvent doesn't work because it's not a major event, so we
	// instead reach into the netmon and grab the callback, and then call
	// it ourselves.
	mon.mu.Lock()
	var cb func(*ChangeDelta)
	for _, c := range mon.cbs {
		cb = c
		break
	}
	mon.mu.Unlock()

	cb(&ChangeDelta{Major: true})

	logf("hello %s", "world")
	if got := logBuffer.String(); got != "hello world\nother message\nhello world\n" {
		t.Errorf("unexpected log buffer contents: %q", got)
	}

	// Canceling the context we passed to LinkChangeLogLimiter should
	// unregister the callback from the netmon.
	cancel()
	synctest.Wait()

	mon.mu.Lock()
	if len(mon.cbs) != 0 {
		t.Errorf("expected no callbacks, got %v", mon.cbs)
	}
	mon.mu.Unlock()
}
