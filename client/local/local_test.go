// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19

package local

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"

	"tailscale.com/tstest/deptest"
	"tailscale.com/tstest/nettest"
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
	nw := nettest.GetNetwork(t)
	ts := nettest.NewHTTPServer(nw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer ts.Close()

	lc := &Client{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nw.Dial(ctx, network, ts.Listener.Addr().String())
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

func TestClientCurrentDNSMode(t *testing.T) {
	nw := nettest.GetNetwork(t)
	ts := nettest.NewHTTPServer(nw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/localapi/v0/dns-mode" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		fmt.Fprint(w, `{"mode":"systemd-resolved"}`)
	}))
	defer ts.Close()

	lc := &Client{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nw.Dial(ctx, network, ts.Listener.Addr().String())
		},
	}
	mode, err := lc.CurrentDNSMode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if mode != "systemd-resolved" {
		t.Errorf("mode=%q, want systemd-resolved", mode)
	}
}

func TestClientCurrentDNSModeErrors(t *testing.T) {
	t.Run("network_error", func(t *testing.T) {
		lc := &Client{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("dial failed")
		}}
		if _, err := lc.CurrentDNSMode(context.Background()); err == nil {
			t.Error("expected error from dial failure")
		}
	})

	t.Run("invalid_json", func(t *testing.T) {
		nw := nettest.GetNetwork(t)
		ts := nettest.NewHTTPServer(nw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "garbage")
		}))
		defer ts.Close()

		lc := &Client{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nw.Dial(ctx, network, ts.Listener.Addr().String())
		}}
		if _, err := lc.CurrentDNSMode(context.Background()); err == nil {
			t.Error("expected JSON error")
		}
	})
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
