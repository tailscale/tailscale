// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/net/bakedroots"
	"tailscale.com/net/connectproxy"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/tstest/tlstest"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/util/eventbus/eventbustest"
)

func fieldsOf(t reflect.Type) (fields []string) {
	for i := range t.NumField() {
		if name := t.Field(i).Name; name != "_" {
			fields = append(fields, name)
		}
	}
	return
}

func TestStatusEqual(t *testing.T) {
	// Verify that the Equal method stays in sync with reality
	equalHandles := []string{"Err", "URL", "NetMap", "Persist", "state"}
	if have := fieldsOf(reflect.TypeFor[Status]()); !reflect.DeepEqual(have, equalHandles) {
		t.Errorf("Status.Equal check might be out of sync\nfields: %q\nhandled: %q\n",
			have, equalHandles)
	}

	tests := []struct {
		a, b *Status
		want bool
	}{
		{
			&Status{},
			nil,
			false,
		},
		{
			nil,
			&Status{},
			false,
		},
		{
			nil,
			nil,
			true,
		},
		{
			&Status{},
			&Status{},
			true,
		},
		{
			&Status{},
			&Status{state: StateAuthenticated},
			false,
		},
	}
	for i, tt := range tests {
		got := tt.a.Equal(tt.b)
		if got != tt.want {
			t.Errorf("%d. Equal = %v; want %v", i, got, tt.want)
		}
	}
}

// tests [canSkipStatus].
func TestCanSkipStatus(t *testing.T) {
	st := new(Status)
	nm1 := &netmap.NetworkMap{}
	nm2 := &netmap.NetworkMap{}

	tests := []struct {
		name   string
		s1, s2 *Status
		want   bool
	}{
		{
			name: "nil-s2",
			s1:   st,
			s2:   nil,
			want: false,
		},
		{
			name: "equal",
			s1:   st,
			s2:   st,
			want: false,
		},
		{
			name: "s1-error",
			s1:   &Status{Err: io.EOF, NetMap: nm1},
			s2:   &Status{NetMap: nm2},
			want: false,
		},
		{
			name: "s1-url",
			s1:   &Status{URL: "foo", NetMap: nm1},
			s2:   &Status{NetMap: nm2},
			want: false,
		},
		{
			name: "s1-persist-diff",
			s1:   &Status{Persist: new(persist.Persist).View(), NetMap: nm1},
			s2:   &Status{NetMap: nm2},
			want: false,
		},
		{
			name: "s1-state-diff",
			s1:   &Status{state: 123, NetMap: nm1},
			s2:   &Status{NetMap: nm2},
			want: false,
		},
		{
			name: "s1-no-netmap1",
			s1:   &Status{NetMap: nil},
			s2:   &Status{NetMap: nm2},
			want: false,
		},
		{
			name: "s1-no-netmap2",
			s1:   &Status{NetMap: nm1},
			s2:   &Status{NetMap: nil},
			want: false,
		},
		{
			name: "skip",
			s1:   &Status{NetMap: nm1},
			s2:   &Status{NetMap: nm2},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canSkipStatus(tt.s1, tt.s2); got != tt.want {
				t.Errorf("canSkipStatus = %v, want %v", got, tt.want)
			}
		})
	}

	want := []string{"Err", "URL", "NetMap", "Persist", "state"}
	if f := fieldsOf(reflect.TypeFor[Status]()); !slices.Equal(f, want) {
		t.Errorf("Status fields = %q; this code was only written to handle fields %q", f, want)
	}
}

func TestRetryableErrors(t *testing.T) {
	errorTests := []struct {
		err  error
		want bool
	}{
		{errNoNoiseClient, true},
		{errNoNodeKey, true},
		{fmt.Errorf("%w: %w", errNoNoiseClient, errors.New("no noise")), true},
		{fmt.Errorf("%w: %w", errHTTPPostFailure, errors.New("bad post")), true},
		{fmt.Errorf("%w: %w", errNoNodeKey, errors.New("not node key")), true},
		{errBadHTTPResponse(429, "too may requests"), true},
		{errBadHTTPResponse(500, "internal server eror"), true},
		{errBadHTTPResponse(502, "bad gateway"), true},
		{errBadHTTPResponse(503, "service unavailable"), true},
		{errBadHTTPResponse(504, "gateway timeout"), true},
		{errBadHTTPResponse(1234, "random error"), false},
	}

	for _, tt := range errorTests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			if isRetryableErrorForTest(tt.err) != tt.want {
				t.Fatalf("retriable: got %v, want %v", tt.err, tt.want)
			}
		})
	}
}

type retryableForTest interface {
	Retryable() bool
}

func isRetryableErrorForTest(err error) bool {
	var ae retryableForTest
	if errors.As(err, &ae) {
		return ae.Retryable()
	}
	return false
}

var liveNetworkTest = flag.Bool("live-network-test", false, "run live network tests")

func TestDirectProxyManual(t *testing.T) {
	if !*liveNetworkTest {
		t.Skip("skipping without --live-network-test")
	}

	bus := eventbustest.NewBus(t)

	dialer := &tsdial.Dialer{}
	dialer.SetNetMon(netmon.NewStatic())

	opts := Options{
		Persist: persist.Persist{},
		GetMachinePrivateKey: func() (key.MachinePrivate, error) {
			return key.NewMachine(), nil
		},
		ServerURL: "https://controlplane.tailscale.com",
		Clock:     tstime.StdClock{},
		Hostinfo: &tailcfg.Hostinfo{
			BackendLogID: "test-backend-log-id",
		},
		DiscoPublicKey: key.NewDisco().Public(),
		Logf:           t.Logf,
		HealthTracker:  health.NewTracker(bus),
		PopBrowserURL: func(url string) {
			t.Logf("PopBrowserURL: %q", url)
		},
		Dialer:       dialer,
		ControlKnobs: &controlknobs.Knobs{},
		Bus:          bus,
	}
	d, err := NewDirect(opts)
	if err != nil {
		t.Fatalf("NewDirect: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	url, err := d.TryLogin(ctx, LoginEphemeral)
	if err != nil {
		t.Fatalf("TryLogin: %v", err)
	}
	t.Logf("URL: %q", url)
}

func TestHTTPSNoProxy(t *testing.T) { testHTTPS(t, false) }

// TestTLSWithProxy verifies we can connect to the control plane via
// an HTTPS proxy.
func TestHTTPSWithProxy(t *testing.T) { testHTTPS(t, true) }

func testHTTPS(t *testing.T, withProxy bool) {
	bakedroots.ResetForTest(t, tlstest.TestRootCA())

	bus := eventbustest.NewBus(t)

	controlLn, err := tls.Listen("tcp", "127.0.0.1:0", tlstest.ControlPlane.ServerTLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer controlLn.Close()

	proxyLn, err := tls.Listen("tcp", "127.0.0.1:0", tlstest.ProxyServer.ServerTLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()

	const requiredAuthKey = "hunter2"
	const someUsername = "testuser"
	const somePassword = "testpass"

	testControl := &testcontrol.Server{
		Logf:           tstest.WhileTestRunningLogger(t),
		RequireAuthKey: requiredAuthKey,
	}
	controlSrv := &http.Server{
		Handler:  testControl,
		ErrorLog: logger.StdLogger(t.Logf),
	}
	go controlSrv.Serve(controlLn)

	const fakeControlIP = "1.2.3.4"
	const fakeProxyIP = "5.6.7.8"

	dialer := &tsdial.Dialer{}
	dialer.SetNetMon(netmon.NewStatic())
	dialer.SetSystemDialerForTest(func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("SplitHostPort(%q): %v", addr, err)
		}
		var d net.Dialer
		if host == fakeControlIP {
			return d.DialContext(ctx, network, controlLn.Addr().String())
		}
		if host == fakeProxyIP {
			return d.DialContext(ctx, network, proxyLn.Addr().String())
		}
		return nil, fmt.Errorf("unexpected dial to %q", addr)
	})

	opts := Options{
		Persist: persist.Persist{},
		GetMachinePrivateKey: func() (key.MachinePrivate, error) {
			return key.NewMachine(), nil
		},
		AuthKey:   requiredAuthKey,
		ServerURL: "https://controlplane.tstest",
		Clock:     tstime.StdClock{},
		Hostinfo: &tailcfg.Hostinfo{
			BackendLogID: "test-backend-log-id",
		},
		DiscoPublicKey: key.NewDisco().Public(),
		Logf:           t.Logf,
		HealthTracker:  health.NewTracker(bus),
		PopBrowserURL: func(url string) {
			t.Logf("PopBrowserURL: %q", url)
		},
		Dialer: dialer,
		Bus:    bus,
	}
	d, err := NewDirect(opts)
	if err != nil {
		t.Fatalf("NewDirect: %v", err)
	}

	d.dnsCache.LookupIPForTest = func(ctx context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "controlplane.tstest":
			return []netip.Addr{netip.MustParseAddr(fakeControlIP)}, nil
		case "proxy.tstest":
			if !withProxy {
				t.Errorf("unexpected DNS lookup for %q with proxy disabled", host)
				return nil, fmt.Errorf("unexpected DNS lookup for %q", host)
			}
			return []netip.Addr{netip.MustParseAddr(fakeProxyIP)}, nil
		}
		t.Errorf("unexpected DNS query for %q", host)
		return []netip.Addr{}, nil
	}

	var proxyReqs atomic.Int64
	if withProxy {
		d.httpc.Transport.(*http.Transport).Proxy = func(req *http.Request) (*url.URL, error) {
			t.Logf("using proxy for %q", req.URL)
			u := &url.URL{
				Scheme: "https",
				Host:   "proxy.tstest:443",
				User:   url.UserPassword(someUsername, somePassword),
			}
			return u, nil
		}

		connectProxy := &http.Server{
			Handler: connectProxyTo(t, "controlplane.tstest:443", controlLn.Addr().String(), &proxyReqs),
		}
		go connectProxy.Serve(proxyLn)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	url, err := d.TryLogin(ctx, LoginEphemeral)
	if err != nil {
		t.Fatalf("TryLogin: %v", err)
	}
	if url != "" {
		t.Errorf("got URL %q, want empty", url)
	}

	if withProxy {
		if got, want := proxyReqs.Load(), int64(1); got != want {
			t.Errorf("proxy CONNECT requests = %d; want %d", got, want)
		}
	}
}

func connectProxyTo(t testing.TB, target, backendAddrPort string, reqs *atomic.Int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != target {
			t.Errorf("invalid CONNECT request to %q; want %q", r.RequestURI, target)
			http.Error(w, "bad target", http.StatusBadRequest)
			return
		}

		r.Header.Set("Authorization", r.Header.Get("Proxy-Authorization")) // for the BasicAuth method. kinda trashy.
		user, pass, ok := r.BasicAuth()
		if !ok || user != "testuser" || pass != "testpass" {
			t.Errorf("invalid CONNECT auth %q:%q; want %q:%q", user, pass, "testuser", "testpass")
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}

		(&connectproxy.Handler{
			Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				c, err := d.DialContext(ctx, network, backendAddrPort)
				if err == nil {
					reqs.Add(1)
				}
				return c, err
			},
			Logf: t.Logf,
		}).ServeHTTP(w, r)
	})
}
