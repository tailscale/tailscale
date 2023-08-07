// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestPortForwardingArguments(t *testing.T) {
	tests := []struct {
		in      string
		wanterr string
		want    *portForward
	}{
		{"", "", nil},
		{"bad port specifier", "cannot parse", nil},
		{"tcp/xyz/example.com", "bad forwarding port", nil},
		{"tcp//example.com", "bad forwarding port", nil},
		{"tcp/2112/", "bad destination", nil},
		{"udp/53/example.com", "unsupported forwarding protocol", nil},
		{"tcp/22/github.com", "", &portForward{Proto: "tcp", Port: 22, Destination: "github.com"}},
	}
	for _, tt := range tests {
		got, goterr := parseForward(tt.in)
		if tt.wanterr != "" {
			if !strings.Contains(goterr.Error(), tt.wanterr) {
				t.Errorf("f(%q).err = %v; want %v", tt.in, goterr, tt.wanterr)
			}
		} else if diff := cmp.Diff(got, tt.want); diff != "" {
			t.Errorf("Parsed forward (-got, +want):\n%s", diff)
		}
	}
}
