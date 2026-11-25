// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netutil

import (
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
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

// TestNewDefaultTransportNoHTTP2 is a regression test for
// tailscale/tailscale#22578. http.DefaultTransport only gets a TLSClientConfig
// from its one-time HTTP/2 setup, so it runs the GODEBUG=http2client=0 case
// in a child process.
func TestNewDefaultTransportNoHTTP2(t *testing.T) {
	if os.Getenv("TS_TEST_NETUTIL_CHILD") == "1" {
		if NewDefaultTransport().TLSClientConfig == nil {
			t.Fatal("TLSClientConfig = nil; want non-nil")
		}
		return
	}
	if NewDefaultTransport().TLSClientConfig == nil {
		t.Error("TLSClientConfig = nil; want non-nil")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNewDefaultTransportNoHTTP2$")
	cmd.Env = append(os.Environ(), "TS_TEST_NETUTIL_CHILD=1", "GODEBUG=http2client=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("with GODEBUG=http2client=0: %v\n%s", err, out)
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
	if tr.TLSClientConfig == nil {
		t.Error("fallback TLSClientConfig = nil; want non-nil")
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

	// The global keys and the per-interface keys for each interface on
	// the machine should all be readable without error, whatever their
	// values.
	for _, p := range []protocol{ipv4, ipv6} {
		on, err := ipForwardingEnabledLinux(p, "")
		if err != nil {
			t.Errorf("global (proto %v): %v", p, err)
		}
		t.Logf("global (proto %v) = %v", p, on)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifaces {
		for _, p := range []protocol{ipv4, ipv6} {
			on, err := ipForwardingEnabledLinux(p, iface.Name)
			if err != nil {
				t.Errorf("%s (proto %v): %v", iface.Name, p, err)
			}
			t.Logf("%s (proto %v) = %v", iface.Name, p, on)
		}
	}
}

func TestCloseWrite(t *testing.T) {
	type closeWriter interface{ CloseWrite() error }
	wrappers := map[string]func(net.Conn) net.Conn{
		"DrainBufConn": func(c net.Conn) net.Conn {
			return NewDrainBufConn(c, nil)
		},
		"AltReadWriteCloserConn": func(c net.Conn) net.Conn {
			return NewAltReadWriteCloserConn(c, c)
		},
	}
	for name, wrap := range wrappers {
		t.Run(name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			s, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			// Half-closing a TCP conn sends EOF to the peer and leaves
			// the other direction open.
			wc := wrap(c)
			if err := wc.(closeWriter).CloseWrite(); err != nil {
				t.Fatalf("CloseWrite: %v", err)
			}
			if b, err := io.ReadAll(s); err != nil || len(b) != 0 {
				t.Fatalf("peer read %q, %v; want EOF", b, err)
			}
			if _, err := s.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 1)
			if _, err := io.ReadFull(wc, b); err != nil || string(b) != "x" {
				t.Fatalf("read after CloseWrite = %q, %v; want %q", b, err, "x")
			}

			// A net.Pipe can't be half-closed.
			p1, p2 := net.Pipe()
			defer p1.Close()
			defer p2.Close()
			if err := wrap(p1).(closeWriter).CloseWrite(); !errors.Is(err, errors.ErrUnsupported) {
				t.Errorf("CloseWrite on net.Pipe = %v, want ErrUnsupported", err)
			}
		})
	}
}
