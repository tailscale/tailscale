// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func TestWindowsDefaultInterfaceIndex(t *testing.T) {
	wm := &winMon{}
	m := &Monitor{om: wm}
	wm.defaultInterface4.get(func() (uint32, error) { return 4, nil })
	wm.defaultInterface6.get(func() (uint32, error) { return 6, nil })
	for _, tt := range []struct {
		family winipcfg.AddressFamily
		index  uint32
	}{
		{windows.AF_INET, 4},
		{windows.AF_INET6, 6},
	} {
		if got, err := m.WindowsDefaultInterfaceIndex(tt.family); got != tt.index || err != nil {
			t.Errorf("WindowsDefaultInterfaceIndex(%v) = %v, %v; want %v, nil", tt.family, got, err, tt.index)
		}
	}
	if _, err := m.WindowsDefaultInterfaceIndex(windows.AF_UNSPEC); err == nil {
		t.Error("WindowsDefaultInterfaceIndex(AF_UNSPEC) succeeded")
	}
}

func TestWindowsDefaultInterfaceCacheClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	wm := &winMon{
		ctx:              ctx,
		cancel:           cancel,
		noDeadlockTicker: time.NewTicker(time.Hour),
	}
	for _, cache := range []*defaultInterfaceCache{&wm.defaultInterface4, &wm.defaultInterface6} {
		cache.get(func() (uint32, error) { return 1, nil })
	}
	if err := wm.Close(); err != nil {
		t.Fatal(err)
	}
	for _, cache := range []*defaultInterfaceCache{&wm.defaultInterface4, &wm.defaultInterface6} {
		for _, want := range []uint32{2, 3} {
			if got, err := cache.get(func() (uint32, error) { return want, nil }); got != want || err != nil {
				t.Errorf("get after Close = %v, %v; want %v, nil", got, err, want)
			}
		}
	}
}

func TestWindowsDefaultInterfaceInvalidation(t *testing.T) {
	for _, event := range []string{"route", "address", "interface"} {
		t.Run(event, func(t *testing.T) {
			// Invalidation must work before Start, when the normal event
			// delivery path would drop the notification.
			wm := &winMon{isActive: func() bool { return false }}
			for _, cache := range []*defaultInterfaceCache{&wm.defaultInterface4, &wm.defaultInterface6} {
				cache.get(func() (uint32, error) { return 1, nil })
			}
			switch event {
			case "route":
				wm.routeChanged(0, nil)
			case "address":
				wm.unicastAddressChanged(0, nil)
			case "interface":
				wm.interfaceChanged(0, nil)
			}
			for _, cache := range []*defaultInterfaceCache{&wm.defaultInterface4, &wm.defaultInterface6} {
				if got, err := cache.get(func() (uint32, error) { return 2, nil }); got != 2 || err != nil {
					t.Errorf("get after %s change = %v, %v; want 2, nil", event, got, err)
				}
			}
		})
	}
}
