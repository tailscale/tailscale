// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"os"
	"net/http/httptest"
	"testing"
	"time"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/net/netns"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

// TestListener_Server ensures that the listener type always keeps the Server
// method, which is used by some external applications to identify a tsnet.Listener
// from other net.Listeners, as well as access the underlying Server.
func TestListener_Server(t *testing.T) {
	s := &Server{}
	ln := listener{s: s}
	if ln.Server() != s {
		t.Errorf("listener.Server() returned %v, want %v", ln.Server(), s)
	}
}

func TestListenerPort(t *testing.T) {
	errNone := errors.New("sentinel start error")

	tests := []struct {
		network string
		addr    string
		wantErr bool
	}{
		{"tcp", ":80", false},
		{"foo", ":80", true},
		{"tcp", ":http", false},  // built-in name to Go; doesn't require cgo, /etc/services
		{"tcp", ":https", false}, // built-in name to Go; doesn't require cgo, /etc/services
		{"tcp", ":gibberishsdlkfj", true},
		{"tcp", ":%!d(string=80)", true}, // issue 6201
	}
	for _, tt := range tests {
		s := &Server{}
		s.initOnce.Do(func() { s.initErr = errNone })
		_, err := s.Listen(tt.network, tt.addr)
		gotErr := err != nil && err != errNone
		if gotErr != tt.wantErr {
			t.Errorf("Listen(%q, %q) error = %v, want %v", tt.network, tt.addr, gotErr, tt.wantErr)
		}
	}
}

var verboseDERP = flag.Bool("verbose-derp", false, "if set, print DERP and STUN logs")
var verboseNodes = flag.Bool("verbose-nodes", false, "if set, print tsnet.Server logs")

func TestConn(t *testing.T) {
	// Corp#4520: don't use netns for tests.
	netns.SetEnabled(false)
	t.Cleanup(func() {
		netns.SetEnabled(true)
	})

	derpLogf := logger.Discard
	if *verboseDERP {
		derpLogf = t.Logf
	}
	derpMap := integration.RunDERPAndSTUN(t, derpLogf, "127.0.0.1")
	control := &testcontrol.Server{
		DERPMap: derpMap,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()
	t.Cleanup(control.HTTPTestServer.Close)
	controlURL := control.HTTPTestServer.URL
	t.Logf("testcontrol listening on %s", controlURL)

	tmp := t.TempDir()
	tmps1 := filepath.Join(tmp, "s1")
	os.MkdirAll(tmps1, 0755)
	s1 := &Server{
		Dir: tmps1,
		ControlURL: controlURL,
		Hostname:   "s1",
		Store:      new(mem.Store),
		Ephemeral:  true,
	}
	defer s1.Close()

	tmps2 := filepath.Join(tmp, "s1")
	os.MkdirAll(tmps2, 0755)
	s2 := &Server{
		Dir: tmps2,
		ControlURL: controlURL,
		Hostname:   "s2",
		Store:      new(mem.Store),
		Ephemeral:  true,
	}
	defer s2.Close()

	if !*verboseNodes {
		s1.Logf = logger.Discard
		s2.Logf = logger.Discard
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s1status, err := s1.Up(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s1ip := s1status.TailscaleIPs[0]
	if _, err := s2.Up(ctx); err != nil {
		t.Fatal(err)
	}

	lc2, err := s2.LocalClient()
	if err != nil {
		t.Fatal(err)
	}

	// ping to make sure the connection is up.
	res, err := lc2.Ping(ctx, s1ip, tailcfg.PingICMP)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ping success: %#+v", res)

	// pass some data through TCP.
	ln, err := s1.Listen("tcp", ":8081")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	w, err := s2.Dial(ctx, "tcp", fmt.Sprintf("%s:8081", s1ip))
	if err != nil {
		t.Fatal(err)
	}

	r, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}

	want := "hello"
	if _, err := io.WriteString(w, want); err != nil {
		t.Fatal(err)
	}

	got := make([]byte, len(want))
	if _, err := io.ReadAtLeast(r, got, len(got)); err != nil {
		t.Fatal(err)
	}
	t.Logf("got: %q", got)
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
