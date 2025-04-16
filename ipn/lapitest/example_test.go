// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package lapitest

import (
	"context"
	"testing"

	"tailscale.com/ipn"
)

func TestClientServer(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Create a server and two clients.
	// Both clients represent the same user to make this work across platforms.
	// On Windows we've been restricting the API usage to a single user at a time.
	// While we're planning on changing this once a better permission model is in place,
	// this test is currently limited to a single user (but more than one client is fine).
	// Alternatively, we could override GOOS via envknobs to test as if we're
	// on a different platform, but that would make the test depend on global state, etc.
	s := NewServer(t, WithLogging(false))
	c1 := s.ClientWithName("User-A")
	c2 := s.ClientWithName("User-A")

	// Start watching the IPN bus as the second client.
	w2, _ := c2.WatchIPNBus(context.Background(), ipn.NotifyInitialPrefs)

	// We're supposed to get a notification about the initial prefs,
	// and WantRunning should be false.
	n, err := w2.Next()
	for ; err == nil; n, err = w2.Next() {
		if n.Prefs == nil {
			// Ignore non-prefs notifications.
			continue
		}
		if n.Prefs.WantRunning() {
			t.Errorf("WantRunning(initial): got %v, want false", n.Prefs.WantRunning())
		}
		break
	}
	if err != nil {
		t.Fatalf("IPNBusWatcher.Next failed: %v", err)
	}

	// Now send an EditPrefs request from the first client to set WantRunning to true.
	change := &ipn.MaskedPrefs{Prefs: ipn.Prefs{WantRunning: true}, WantRunningSet: true}
	gotPrefs, err := c1.EditPrefs(ctx, change)
	if err != nil {
		t.Fatalf("EditPrefs failed: %v", err)
	}
	if !gotPrefs.WantRunning {
		t.Fatalf("EditPrefs.WantRunning: got %v, want true", gotPrefs.WantRunning)
	}

	// We can check the backend directly to see if the prefs were set correctly.
	if gotWantRunning := s.Backend().Prefs().WantRunning(); !gotWantRunning {
		t.Fatalf("Backend.Prefs.WantRunning: got %v, want true", gotWantRunning)
	}

	// And can also wait for the second client with an IPN bus watcher to receive the notification
	// about the prefs change.
	n, err = w2.Next()
	for ; err == nil; n, err = w2.Next() {
		if n.Prefs == nil {
			// Ignore non-prefs notifications.
			continue
		}
		if !n.Prefs.WantRunning() {
			t.Fatalf("WantRunning(changed): got %v, want true", n.Prefs.WantRunning())
		}
		break
	}
	if err != nil {
		t.Fatalf("IPNBusWatcher.Next failed: %v", err)
	}
}
