// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsdial

import (
	"context"
	"flag"
	"net"
	"testing"
	"time"
)

var dohBase = flag.String("doh-base", "", "DoH base URL for manual DoH tests; e.g. \"http://100.68.82.120:47830/dns-query\"")

func TestDoHResolve(t *testing.T) {
	if *dohBase == "" {
		t.Skip("skipping manual test without --doh-base= set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var r net.Resolver
	r.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return &dohConn{ctx: ctx, baseURL: *dohBase}, nil
	}
	addrs, err := r.LookupIP(ctx, "ip4", "google.com.")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Got: %q", addrs)
}
