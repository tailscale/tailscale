// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/util/cloudenv"
)

func TestCloudInfo_AWS(t *testing.T) {
	const (
		mac1      = "06:1d:00:00:00:00"
		mac2      = "06:1d:00:00:00:01"
		publicV4  = "1.2.3.4"
		otherV4_1 = "5.6.7.8"
		otherV4_2 = "11.12.13.14"
		v6addr    = "2001:db8::1"

		macsPrefix = "/latest/meta-data/network/interfaces/macs/"
	)
	// Launch a fake AWS IMDS server
	fake := &fakeIMDS{
		tb: t,
		paths: map[string]string{
			macsPrefix: mac1 + "\n" + mac2,
			// This is the "main" public IP address for the instance
			macsPrefix + mac1 + "/public-ipv4s": publicV4,

			// There's another interface with two public IPs
			// attached to it and an IPv6 address, all of which we
			// should discover.
			macsPrefix + mac2 + "/public-ipv4s": otherV4_1 + "\n" + otherV4_2,
			macsPrefix + mac2 + "/ipv6s":        v6addr,
		},
	}

	srv := httptest.NewServer(fake)
	defer srv.Close()

	ci := newCloudInfo(t.Logf)
	ci.cloud = cloudenv.AWS
	ci.endpoint = srv.URL

	ips, err := ci.GetPublicIPs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantIPs := []netip.Addr{
		netip.MustParseAddr(publicV4),
		netip.MustParseAddr(otherV4_1),
		netip.MustParseAddr(otherV4_2),
		netip.MustParseAddr(v6addr),
	}
	if !slices.Equal(ips, wantIPs) {
		t.Fatalf("got %v, want %v", ips, wantIPs)
	}
}

func TestCloudInfo_AWSNotPublic(t *testing.T) {
	returns404 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" && r.URL.Path == "/latest/api/token" {
			w.Header().Set("Server", "EC2ws")
			w.Write([]byte("fake-imds-token"))
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(returns404)
	defer srv.Close()

	ci := newCloudInfo(t.Logf)
	ci.cloud = cloudenv.AWS
	ci.endpoint = srv.URL

	// If the IMDS server doesn't return any public IPs, it's not an error
	// and we should just get an empty list.
	ips, err := ci.GetPublicIPs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 0 {
		t.Fatalf("got %v, want none", ips)
	}
}

type fakeIMDS struct {
	tb    testing.TB
	paths map[string]string
}

func (f *fakeIMDS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.tb.Logf("%s %s", r.Method, r.URL.Path)
	path := r.URL.Path

	// Handle the /latest/api/token case
	const token = "fake-imds-token"
	if r.Method == "PUT" && path == "/latest/api/token" {
		w.Header().Set("Server", "EC2ws")
		w.Write([]byte(token))
		return
	}

	// Otherwise, require the IMDSv2 token to be set
	if r.Header.Get("X-aws-ec2-metadata-token") != token {
		f.tb.Errorf("missing or invalid IMDSv2 token")
		http.Error(w, "missing or invalid IMDSv2 token", http.StatusForbidden)
		return
	}

	if v, ok := f.paths[path]; ok {
		w.Write([]byte(v))
		return
	}
	http.NotFound(w, r)
}
