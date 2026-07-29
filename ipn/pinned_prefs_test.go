// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import "testing"

func TestPinnedItemKey(t *testing.T) {
	if got := (PinnedItem{ID: "nABC"}).Key(); got != "nABC" {
		t.Errorf("node Key = %q; want nABC", got)
	}
	if got := (PinnedItem{Service: "svc:web"}).Key(); got != "svc:web" {
		t.Errorf("service Key = %q; want svc:web", got)
	}
}

func TestPinnedPrefsEquals(t *testing.T) {
	base := PinnedPrefs{
		Devices:   []PinnedItem{{ID: "n1"}, {ID: "n2"}},
		ExitNodes: []PinnedItem{{ID: "n3"}},
		Services:  []PinnedItem{{Service: "svc:web"}},
	}
	tests := []struct {
		name string
		a, b PinnedPrefs
		want bool
	}{
		{"equal", base, base, true},
		{"zero_equal", PinnedPrefs{}, PinnedPrefs{}, true},
		{
			"device_differs",
			PinnedPrefs{Devices: []PinnedItem{{ID: "n1"}}},
			PinnedPrefs{Devices: []PinnedItem{{ID: "n2"}}},
			false,
		},
		{
			"order_significant",
			PinnedPrefs{Devices: []PinnedItem{{ID: "n1"}, {ID: "n2"}}},
			PinnedPrefs{Devices: []PinnedItem{{ID: "n2"}, {ID: "n1"}}},
			false,
		},
		{
			"service_differs",
			PinnedPrefs{Services: []PinnedItem{{Service: "svc:web"}}},
			PinnedPrefs{Services: []PinnedItem{{Service: "svc:db"}}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.Equals(tt.b); got != tt.want {
				t.Errorf("Equals = %v; want %v", got, tt.want)
			}
		})
	}
}
