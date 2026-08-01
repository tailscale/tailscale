// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package serviceclientprefs

import (
	"sync"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
	"tailscale.com/types/logger"
)

// fakeBackend is a minimal [ipnext.SafeBackend] for tests. Only Clock and TailscaleVarRoot are
// used by the extension; Sys is never called.
type fakeBackend struct {
	clock   tstime.Clock
	varRoot string
}

func (f *fakeBackend) Sys() *tsd.System         { return nil }
func (f *fakeBackend) Clock() tstime.Clock      { return f.clock }
func (f *fakeBackend) TailscaleVarRoot() string { return f.varRoot }

// fakeHost is a minimal [ipnext.Host] that records the notifies the extension publishes.
type fakeHost struct {
	ipnext.Host

	mu       sync.Mutex
	notified []ipn.Notify
}

func (h *fakeHost) SendNotifyAsync(n ipn.Notify) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.notified = append(h.notified, n)
}

// lastServiceClientPrefs returns the payload of the most recent published notify, or nil if
// nothing has been published.
func (h *fakeHost) lastServiceClientPrefs() *ipn.ServiceClientPrefsNotify {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := len(h.notified) - 1; i >= 0; i-- {
		if p := h.notified[i].ServiceClientPrefs; p != nil {
			return p
		}
	}
	return nil
}

// newTestExtension returns an extension backed by a temp var root and a fixed test clock, with its
// current profile set to pid.
func newTestExtension(t *testing.T, pid ipn.ProfileID) *extension {
	t.Helper()
	return newTestExtensionInDir(t, pid, t.TempDir())
}

// newTestExtensionInDir is like newTestExtension but uses the given var root, which may be empty
// to force the in-memory store fallback.
func newTestExtensionInDir(t *testing.T, pid ipn.ProfileID, varRoot string) *extension {
	t.Helper()
	e := &extension{
		logf: logger.Discard,
		host: &fakeHost{},
		sb: &fakeBackend{
			clock:   tstest.NewClock(tstest.ClockOpts{Start: time.Now()}),
			varRoot: varRoot,
		},
	}
	e.onChangeProfile((&ipn.LoginProfile{ID: pid}).View(), ipn.PrefsView{}, false)
	return e
}

func TestNoVarRootUsesMemory(t *testing.T) {
	e := newTestExtensionInDir(t, "pid", "") // empty var root forces the in-memory fallback

	if _, err := e.setServiceClientPref(apitype.ServiceClientPrefRequest{Key: "ssh:22", Client: "terminal"}); err != nil {
		t.Fatal(err)
	}
	got, err := e.serviceClientPrefs()
	if err != nil {
		t.Fatal(err)
	}
	if got["ssh:22"].Client != "terminal" {
		t.Errorf("in-memory store: got %v, want Client=terminal", got["ssh:22"])
	}
}
