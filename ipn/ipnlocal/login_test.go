// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"testing"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
)

// TestBeginLoginReusesAuthURL verifies that a repeated login request does not
// replace an existing control client or discard an available auth URL.
func TestBeginLoginReusesAuthURL(t *testing.T) {
	lb := newLocalBackendWithTestControl(t, false, func(tb testing.TB, opts controlclient.Options) controlclient.Client {
		return newClient(tb, opts)
	})
	if err := lb.Start(ipn.Options{UpdatePrefs: &ipn.Prefs{WantRunning: true}}); err != nil {
		t.Fatal(err)
	}
	const loginURL = "https://login.tailscale.com/a/test-reuse"
	lb.mu.Lock()
	originalClient := lb.cc
	lb.setAuthURLLocked(loginURL)
	lb.mu.Unlock()

	watcher := newNotificationWatcher(t, lb, nil)
	watcher.watch(0, []wantedNotification{{
		name: "reused authentication URL",
		cond: func(_ testing.TB, _ ipnauth.Actor, n *ipn.Notify) bool {
			return n.BrowseToURL != nil && *n.BrowseToURL == loginURL
		},
	}})
	if err := lb.beginLoginAs(context.Background(), nil, beginLoginOpts{}); err != nil {
		t.Fatal(err)
	}
	watcher.check()
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if lb.cc != originalClient {
		t.Error("login replaced the existing control client")
	}
	if lb.authURL != loginURL {
		t.Errorf("authURL = %q, want %q", lb.authURL, loginURL)
	}
}

// TestBeginLoginPendingWithoutURL verifies that a second login request doesn't
// reset the control client merely because the auth URL hasn't arrived yet.
func TestBeginLoginPendingWithoutURL(t *testing.T) {
	lb := newLocalBackendWithTestControl(t, false, func(tb testing.TB, opts controlclient.Options) controlclient.Client {
		return newClient(tb, opts)
	})
	if err := lb.beginLoginAs(context.Background(), nil, beginLoginOpts{}); err != nil {
		t.Fatal(err)
	}
	lb.mu.Lock()
	originalClient := lb.cc
	lb.mu.Unlock()
	if originalClient == nil {
		t.Fatal("beginLoginAs did not start a control client")
	}
	if err := lb.beginLoginAs(context.Background(), nil, beginLoginOpts{}); err != nil {
		t.Fatal(err)
	}
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if lb.cc != originalClient {
		t.Error("second login replaced the in-flight control client")
	}
}

// TestBeginLoginWithControlURL verifies that masked configuration is passed to
// Start instead of triggering an EditPrefs WantRunning transition first.
func TestBeginLoginWithControlURL(t *testing.T) {
	lb := newLocalBackendWithTestControl(t, false, func(tb testing.TB, opts controlclient.Options) controlclient.Client {
		return newClient(tb, opts)
	})
	const controlURL = "https://control.example.test"
	if err := lb.beginLoginAs(context.Background(), nil, beginLoginOpts{
		prefs: &ipn.MaskedPrefs{
			Prefs:         ipn.Prefs{ControlURL: controlURL},
			ControlURLSet: true,
		},
	}); err != nil {
		t.Fatal(err)
	}
	prefs := lb.Prefs()
	if !prefs.WantRunning() {
		t.Error("WantRunning = false, want true")
	}
	if got := prefs.ControlURL(); got != controlURL {
		t.Errorf("ControlURL = %q, want %q", got, controlURL)
	}
}

// TestBeginLoginAuthKey verifies that an auth-key login clears LoggedOut and
// enables WantRunning as part of the Start preferences.
func TestBeginLoginAuthKey(t *testing.T) {
	lb := newLocalBackendWithTestControl(t, false, func(tb testing.TB, opts controlclient.Options) controlclient.Client {
		return newClient(tb, opts)
	})
	lb.ForTest().SetPrefs(&ipn.Prefs{LoggedOut: true})
	if err := lb.beginLoginAs(context.Background(), nil, beginLoginOpts{
		authKey: "tskey-auth-test",
	}); err != nil {
		t.Fatal(err)
	}
	prefs := lb.Prefs()
	if !prefs.WantRunning() {
		t.Error("WantRunning = false, want true")
	}
	if prefs.LoggedOut() {
		t.Error("LoggedOut = true, want false")
	}
}
