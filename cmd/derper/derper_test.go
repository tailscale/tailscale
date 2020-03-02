// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"testing"
)

func TestProdAutocertHostPolicy(t *testing.T) {
	tests := []struct {
		in     string
		wantOK bool
	}{
		{"derp.tailscale.com", true},
		{"derp.tailscale.com.", true},
		{"derp1.tailscale.com", true},
		{"derp2.tailscale.com", true},
		{"derp02.tailscale.com", true},
		{"derp-nyc.tailscale.com", true},
		{"derpfoo.tailscale.com", false},
		{"derp02.bar.tailscale.com", false},
		{"example.net", false},
	}
	for _, tt := range tests {
		got := prodAutocertHostPolicy(context.Background(), tt.in) == nil
		if got != tt.wantOK {
			t.Errorf("f(%q) = %v; want %v", tt.in, got, tt.wantOK)
		}
	}

}
