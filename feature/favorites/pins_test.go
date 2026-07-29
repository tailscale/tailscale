// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package favorites

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/feature/favorites/pintype"
	"tailscale.com/ipn"
)

func TestPinsSetAndGet(t *testing.T) {
	e := newTestExtension(t, "pid")

	// Set devices and services in one request; exit-nodes untouched.
	got, err := e.setPins(pintype.SetRequest{
		Pins: pintype.Set{
			Devices:  []pintype.Device{{ID: "n1"}, {ID: "n2"}},
			Services: []pintype.Service{{Name: "svc:web"}},
		},
		DevicesSet:  true,
		ServicesSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := pintype.Set{
		Devices:  []pintype.Device{{ID: "n1"}, {ID: "n2"}},
		Services: []pintype.Service{{Name: "svc:web"}},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("after set (-want +got):\n%s", diff)
	}

	// Replace only devices; services must be preserved (not named).
	got, err = e.setPins(pintype.SetRequest{
		Pins:       pintype.Set{Devices: []pintype.Device{{ID: "n3"}}},
		DevicesSet: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	want = pintype.Set{
		Devices:  []pintype.Device{{ID: "n3"}},
		Services: []pintype.Service{{Name: "svc:web"}},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("after partial replace (-want +got):\n%s", diff)
	}

	// Clear devices with an empty, but Set, list.
	got, err = e.setPins(pintype.SetRequest{DevicesSet: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Devices) != 0 {
		t.Errorf("devices = %v; want empty", got.Devices)
	}
	if len(got.Services) != 1 {
		t.Errorf("services = %v; want preserved", got.Services)
	}
}

func TestPinsPersistAcrossStoreReopen(t *testing.T) {
	e := newTestExtension(t, "pid")
	if _, err := e.setPins(pintype.SetRequest{
		Pins:       pintype.Set{Devices: []pintype.Device{{ID: "n1"}}},
		DevicesSet: true,
	}); err != nil {
		t.Fatal(err)
	}

	// Rebuild the store so the next read reopens the file from disk.
	e.onChangeProfile((&ipn.LoginProfile{ID: "pid"}).View(), ipn.PrefsView{}, false)

	got, err := e.currentPins()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Devices) != 1 || got.Devices[0].ID != "n1" {
		t.Errorf("after reopen, got %v, want devices=[n1]", got.Devices)
	}
}

func TestPinsNoCurrentProfileReturnsEmpty(t *testing.T) {
	e := newTestExtension(t, "") // no current profile

	got, err := e.currentPins()
	if err != nil {
		t.Fatalf("want nil error for no current profile, got %v", err)
	}
	if !got.Equals(pintype.Set{}) {
		t.Errorf("want zero pintype.Set, got %#v", got)
	}
}
