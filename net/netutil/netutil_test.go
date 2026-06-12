// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netutil

import (
	"io"
	"net"
	"net/http"
	"runtime"
	"testing"
	"time"
)

type conn struct {
	net.Conn
}

func TestOneConnListener(t *testing.T) {
	c1 := new(conn)
	a1 := dummyAddr("a1")

	// Two Accepts
	ln := NewOneConnListener(c1, a1)
	if got := ln.Addr(); got != a1 {
		t.Errorf("Addr = %#v; want %#v", got, a1)
	}
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if c != c1 {
		t.Fatalf("didn't get c1; got %p", c)
	}
	c, err = ln.Accept()
	if err != io.EOF {
		t.Errorf("got %v; want EOF", err)
	}
	if c != nil {
		t.Errorf("unexpected non-nil Conn")
	}

	// Close before Accept
	ln = NewOneConnListener(c1, a1)
	ln.Close()
	_, err = ln.Accept()
	if err != io.EOF {
		t.Fatalf("got %v; want EOF", err)
	}

	// Implicit addr
	ln = NewOneConnListener(c1, nil)
	if ln.Addr() == nil {
		t.Errorf("nil Addr")
	}
}

// roundTripperFunc is an http.RoundTripper that is not a *http.Transport,
// used to exercise the fallback path of NewDefaultTransport.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNewDefaultTransport(t *testing.T) {
	// Standard case: http.DefaultTransport is still a *http.Transport, so we
	// get a clone of it with the stdlib defaults.
	tr := NewDefaultTransport()
	if tr == nil {
		t.Fatal("got nil transport")
	}
	if got, want := tr.MaxIdleConns, 100; got != want {
		t.Errorf("MaxIdleConns = %d; want %d", got, want)
	}
	if got, want := tr.IdleConnTimeout, 90*time.Second; got != want {
		t.Errorf("IdleConnTimeout = %v; want %v", got, want)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 = false; want true")
	}

	// Regression case: an application has replaced http.DefaultTransport with
	// a RoundTripper that is not a *http.Transport. NewDefaultTransport must
	// not panic and must still return a usable transport with stdlib defaults.
	orig := http.DefaultTransport
	defer func() { http.DefaultTransport = orig }()
	http.DefaultTransport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, nil
	})

	tr = NewDefaultTransport()
	if tr == nil {
		t.Fatal("got nil transport on fallback path")
	}
	if got, want := tr.MaxIdleConns, 100; got != want {
		t.Errorf("fallback MaxIdleConns = %d; want %d", got, want)
	}
	if got, want := tr.IdleConnTimeout, 90*time.Second; got != want {
		t.Errorf("fallback IdleConnTimeout = %v; want %v", got, want)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("fallback ForceAttemptHTTP2 = false; want true")
	}
	if tr.DialContext == nil {
		t.Error("fallback DialContext = nil; want non-nil")
	}
	if tr.Proxy == nil {
		t.Error("fallback Proxy = nil; want non-nil")
	}
}

func TestIPForwardingEnabledLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("skipping on %s", runtime.GOOS)
	}
	got, err := ipForwardingEnabledLinux(ipv4, "some-not-found-interface")
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Errorf("got true; want false")
	}
}
