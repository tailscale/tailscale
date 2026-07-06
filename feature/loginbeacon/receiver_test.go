// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_loginbeacon

package loginbeacon

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestSenderReceiverLocal exercises the full multicast handshake on the
// loopback multicast group: a Sender starts advertising, a Receiver sees
// the beacon, Approve completes, and the auth URL round-trips.
//
// This test needs a machine where the loopback interface can carry
// multicast to 239.255.42.42:41421. Most Linux/macOS defaults do; if the
// environment doesn't, the test is skipped.
func TestSenderReceiverLocal(t *testing.T) {
	logf := func(format string, args ...any) { t.Logf(format, args...) }

	beacons := make(chan Beacon, 1)
	urls := make(chan string, 1)

	rctx, rcancel := context.WithCancel(context.Background())
	defer rcancel()
	r, err := StartReceiver(rctx, ReceiverConfig{
		OnBeacon:   func(b Beacon) { beacons <- b },
		OnAuthURL:  func(u string) { urls <- u },
		URLAllowed: func(string) bool { return true },
		Logf:       logf,
	})
	if err != nil {
		t.Skipf("cannot start receiver on this host (multicast unavailable?): %v", err)
	}
	defer r.Stop()

	const wantURL = "https://login.tailscale.com/a/deadbeef"
	authURL := wantURL
	var mu sync.Mutex
	getURL := func() string { mu.Lock(); defer mu.Unlock(); return authURL }

	sctx, scancel := context.WithCancel(context.Background())
	defer scancel()
	s, err := Start(sctx, Config{
		Hostname:   "test-appliance",
		DeviceKind: "appliance",
		DeviceID:   "test-device-id",
		AuthURL:    getURL,
		Logf:       logf,
	})
	if err != nil {
		t.Fatalf("Start sender: %v", err)
	}
	defer s.Stop()

	var b Beacon
	select {
	case b = <-beacons:
	case <-time.After(15 * time.Second):
		t.Fatal("did not observe a beacon within 15s")
	}
	if b.Hostname != "test-appliance" {
		t.Fatalf("Hostname = %q; want test-appliance", b.Hostname)
	}

	if err := r.Approve(b.RequestID); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	select {
	case gotURL := <-urls:
		if gotURL != wantURL {
			t.Fatalf("url = %q; want %q", gotURL, wantURL)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not receive decrypted URL within 5s")
	}
}

func TestIgnoreSuppressesSubsequentBeacons(t *testing.T) {
	logf := func(format string, args ...any) { t.Logf(format, args...) }

	beacons := make(chan Beacon, 4)

	rctx, rcancel := context.WithCancel(context.Background())
	defer rcancel()
	r, err := StartReceiver(rctx, ReceiverConfig{
		OnBeacon:   func(b Beacon) { beacons <- b },
		OnAuthURL:  func(string) {},
		URLAllowed: func(string) bool { return true },
		Logf:       logf,
	})
	if err != nil {
		t.Skipf("cannot start receiver: %v", err)
	}
	defer r.Stop()

	sctx, scancel := context.WithCancel(context.Background())
	defer scancel()
	s, err := Start(sctx, Config{
		Hostname:   "test",
		DeviceKind: "appliance",
		DeviceID:   "id",
		AuthURL:    func() string { return "https://login.tailscale.com/a/x" },
		Logf:       logf,
	})
	if err != nil {
		t.Fatalf("Start sender: %v", err)
	}
	defer s.Stop()

	select {
	case b := <-beacons:
		r.Ignore(b.RequestID)
	case <-time.After(15 * time.Second):
		t.Fatal("no beacon observed")
	}
	// Even with the sender continuing to broadcast, no further OnBeacon
	// should fire for the same session.
	select {
	case b := <-beacons:
		t.Fatalf("received duplicate beacon after Ignore: %+v", b)
	case <-time.After(2 * beaconInterval):
	}
}

func TestDefaultURLAllowed(t *testing.T) {
	cases := map[string]bool{
		"https://login.tailscale.com/x":  true,
		"https://foo.tailscale.com/y":    true,
		"http://login.tailscale.com/x":   false,
		"https://evil.example.com/x":     false,
		"https://tailscale.com.evil.com": false,
		"":                               false,
	}
	for u, want := range cases {
		if got := DefaultURLAllowed(u); got != want {
			t.Errorf("DefaultURLAllowed(%q) = %v; want %v", u, got, want)
		}
	}
}
