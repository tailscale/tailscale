// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnscache

import (
	"context"
	"flag"
	"net"
	"testing"
	"time"
)

var dialTest = flag.String("dial-test", "", "if non-empty, addr:port to test dial")

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"172.16.1.100", true},
		{"192.168.1.1", true},
		{"1.2.3.4", false},
	}

	for _, test := range tests {
		if got := isPrivateIP(net.ParseIP(test.ip)); got != test.want {
			t.Errorf("isPrivateIP(%q)=%v, want %v", test.ip, got, test.want)
		}
	}
}

func TestDialer(t *testing.T) {
	if *dialTest == "" {
		t.Skip("skipping; --dial-test is blank")
	}
	r := new(Resolver)
	var std net.Dialer
	dialer := Dialer(std.DialContext, r)
	t0 := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := dialer(ctx, "tcp", *dialTest)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("dialed in %v", time.Since(t0))
	c.Close()
}
