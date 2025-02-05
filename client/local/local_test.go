// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19

package local

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale.com/tstest/deptest"
	"tailscale.com/types/key"
)

func TestGetServeConfigFromJSON(t *testing.T) {
	sc, err := getServeConfigFromJSON([]byte("null"))
	if sc != nil {
		t.Errorf("want nil for null")
	}
	if err != nil {
		t.Errorf("reading null: %v", err)
	}

	sc, err = getServeConfigFromJSON([]byte(`{"TCP":{}}`))
	if err != nil {
		t.Errorf("reading object: %v", err)
	} else if sc == nil {
		t.Errorf("want non-nil for object")
	} else if sc.TCP == nil {
		t.Errorf("want non-nil TCP for object")
	}
}

func TestWhoIsPeerNotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer ts.Close()

	lc := &Client{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var std net.Dialer
			return std.DialContext(ctx, network, ts.Listener.Addr().(*net.TCPAddr).String())
		},
	}
	var k key.NodePublic
	if err := k.UnmarshalText([]byte("nodekey:5c8f86d5fc70d924e55f02446165a5dae8f822994ad26bcf4b08fd841f9bf261")); err != nil {
		t.Fatal(err)
	}
	res, err := lc.WhoIsNodeKey(context.Background(), k)
	if err != ErrPeerNotFound {
		t.Errorf("got (%v, %v), want ErrPeerNotFound", res, err)
	}
	res, err = lc.WhoIs(context.Background(), "1.2.3.4:5678")
	if err != ErrPeerNotFound {
		t.Errorf("got (%v, %v), want ErrPeerNotFound", res, err)
	}
}

func TestDeps(t *testing.T) {
	deptest.DepChecker{
		BadDeps: map[string]string{
			// Make sure we don't again accidentally bring in a dependency on
			// drive or its transitive dependencies
			"testing":                        "do not use testing package in production code",
			"tailscale.com/drive/driveimpl":  "https://github.com/tailscale/tailscale/pull/10631",
			"github.com/studio-b12/gowebdav": "https://github.com/tailscale/tailscale/pull/10631",
		},
	}.Check(t)
}
