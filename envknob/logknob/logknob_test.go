// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package logknob

import (
	"bytes"
	"fmt"
	"testing"

	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/util/set"
)

var testKnob = NewLogKnob(
	"TS_TEST_LOGKNOB",
	"https://tailscale.com/cap/testing",
)

// Static type assertion for our interface type.
var _ NetMap = &netmap.NetworkMap{}

func TestLogKnob(t *testing.T) {
	t.Run("Default", func(t *testing.T) {
		if testKnob.shouldLog() {
			t.Errorf("expected default shouldLog()=false")
		}
		assertNoLogs(t)
	})
	t.Run("Manual", func(t *testing.T) {
		t.Cleanup(func() { testKnob.Set(false) })

		assertNoLogs(t)
		testKnob.Set(true)
		if !testKnob.shouldLog() {
			t.Errorf("expected shouldLog()=true")
		}
		assertLogs(t)
	})
	t.Run("Env", func(t *testing.T) {
		t.Cleanup(func() {
			envknob.Setenv("TS_TEST_LOGKNOB", "")
		})

		assertNoLogs(t)
		if testKnob.shouldLog() {
			t.Errorf("expected default shouldLog()=false")
		}

		envknob.Setenv("TS_TEST_LOGKNOB", "true")
		if !testKnob.shouldLog() {
			t.Errorf("expected shouldLog()=true")
		}
		assertLogs(t)
	})
	t.Run("NetMap", func(t *testing.T) {
		t.Cleanup(func() { testKnob.cap.Store(false) })

		assertNoLogs(t)
		if testKnob.shouldLog() {
			t.Errorf("expected default shouldLog()=false")
		}

		testKnob.UpdateFromNetMap(&netmap.NetworkMap{
			AllCaps: set.Of(tailcfg.NodeCapability("https://tailscale.com/cap/testing")),
		})
		if !testKnob.shouldLog() {
			t.Errorf("expected shouldLog()=true")
		}
		assertLogs(t)
	})
}

func assertLogs(t *testing.T) {
	var buf bytes.Buffer
	logf := func(format string, args ...any) {
		fmt.Fprintf(&buf, format, args...)
	}

	testKnob.Do(logf, "hello %s", "world")
	const want = "hello world"
	if got := buf.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func assertNoLogs(t *testing.T) {
	var buf bytes.Buffer
	logf := func(format string, args ...any) {
		fmt.Fprintf(&buf, format, args...)
	}

	testKnob.Do(logf, "hello %s", "world")
	if got := buf.String(); got != "" {
		t.Errorf("expected no logs, but got: %q", got)
	}
}
