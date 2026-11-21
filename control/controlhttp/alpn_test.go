// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package controlhttp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"

	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp/controlhttpcommon"
	"tailscale.com/control/controlhttp/controlhttpserver"
	"tailscale.com/health"
	"tailscale.com/types/key"
	"tailscale.com/util/eventbus/eventbustest"
)

type alpnServerResult struct {
	conn    *controlbase.Conn // non-nil if the smuggled ALPN handshake was used
	viaALPN bool
	err     error
}

// startALPNServer starts a TLS listener that accepts ts2021 connections via
// the smuggled ALPN handshake, falling back to serving the regular HTTP
// upgrade handler for clients that don't use it.
func startALPNServer(t *testing.T, serverKey key.MachinePrivate, earlyWrite func(int, io.Writer) error) (addr *net.TCPAddr, results chan alpnServerResult) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	results = make(chan alpnServerResult, 1)
	base := tlsConfig(t)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				cbConn, tlsConn, err := controlhttpserver.AcceptALPNTLS(ctx, c, base, serverKey, earlyWrite)
				if err != nil {
					results <- alpnServerResult{err: err}
					return
				}
				if cbConn != nil {
					results <- alpnServerResult{conn: cbConn, viaALPN: true}
					return
				}
				// Client didn't smuggle a handshake; serve the HTTP
				// upgrade handler on the TLS conn.
				srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					cbConn, err := controlhttpserver.AcceptHTTP(ctx, w, r, serverKey, earlyWrite)
					results <- alpnServerResult{conn: cbConn, err: err}
				})}
				srv.Serve(newOneConnListener(tlsConn, ln.Addr()))
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr), results
}

// oneConnListener is a net.Listener that returns a single conn and then
// ErrClosed on subsequent Accepts.
type oneConnListener struct {
	conn net.Conn
	addr net.Addr
	ch   chan net.Conn
}

func newOneConnListener(c net.Conn, addr net.Addr) *oneConnListener {
	ch := make(chan net.Conn, 1)
	ch <- c
	close(ch)
	return &oneConnListener{conn: c, addr: addr, ch: ch}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	c, ok := <-l.ch
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}

func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.addr }

func newALPNTestDialer(t *testing.T, clientKey key.MachinePrivate, serverPub key.MachinePublic) *Dialer {
	return &Dialer{
		Hostname:             "localhost",
		MachineKey:           clientKey,
		ControlKey:           serverPub,
		ProtocolVersion:      1,
		Logf:                 t.Logf,
		omitCertErrorLogging: true,
		HealthTracker:        health.NewTracker(eventbustest.NewBus(t)),
		proxyFunc:            func(*http.Request) (*url.URL, error) { return nil, nil },
	}
}

func testALPNRoundTrip(t *testing.T, conn *ClientConn, results chan alpnServerResult, wantViaALPN bool) {
	t.Helper()
	res := <-results
	if res.err != nil {
		t.Fatalf("server accept: %v", res.err)
	}
	defer res.conn.Close()
	if res.viaALPN != wantViaALPN {
		t.Errorf("server got conn viaALPN=%v; want %v", res.viaALPN, wantViaALPN)
	}

	// Verify data flows both ways over the Noise conn.
	const c2s = "hello from client"
	const s2c = "hello from server"
	errc := make(chan error, 1)
	go func() {
		buf := make([]byte, len(c2s))
		if _, err := io.ReadFull(res.conn, buf); err != nil {
			errc <- err
			return
		}
		if string(buf) != c2s {
			errc <- fmt.Errorf("server read %q; want %q", buf, c2s)
			return
		}
		_, err := io.WriteString(res.conn, s2c)
		errc <- err
	}()
	if _, err := io.WriteString(conn, c2s); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, len(s2c))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf) != s2c {
		t.Fatalf("client read %q; want %q", buf, s2c)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server I/O: %v", err)
	}
}

// TestALPNHandshake verifies that a client can smuggle its Noise handshake
// initiation in the TLS ClientHello ALPN list and speak ts2021 directly over
// the TLS stream, with no HTTP layer.
func TestALPNHandshake(t *testing.T) {
	client, server := key.NewMachine(), key.NewMachine()

	const earlyWriteMsg = "Hello, world!"
	earlyWrite := func(protocolVersion int, w io.Writer) error {
		if protocolVersion != 1 {
			return fmt.Errorf("unexpected protocol version %d", protocolVersion)
		}
		_, err := io.WriteString(w, earlyWriteMsg)
		return err
	}

	addr, results := startALPNServer(t, server, earlyWrite)

	a := newALPNTestDialer(t, client, server.Public())
	u := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort("localhost", strconv.Itoa(addr.Port)),
		Path:   serverUpgradePath,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := a.dialURL(ctx, u, netip.Addr{}, "")
	if err != nil {
		t.Fatalf("dialURL: %v", err)
	}
	defer conn.Close()

	if peer := conn.Peer(); peer != server.Public() {
		t.Fatalf("client got peer %v; want %v", peer, server.Public())
	}
	buf := make([]byte, len(earlyWriteMsg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("reading early write: %v", err)
	}
	if string(buf) != earlyWriteMsg {
		t.Fatalf("early write = %q; want %q", buf, earlyWriteMsg)
	}

	testALPNRoundTrip(t, conn, results, true)
}

// TestALPNFallback verifies that when the server doesn't understand the
// smuggled ALPN handshake, the client falls back to the regular HTTP upgrade
// on the same TLS connection.
func TestALPNFallback(t *testing.T) {
	client, server := key.NewMachine(), key.NewMachine()

	results := make(chan alpnServerResult, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cbConn, err := controlhttpserver.AcceptHTTP(context.Background(), w, r, server, nil)
		results <- alpnServerResult{conn: cbConn, err: err}
	})

	httpsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	httpsServer := &http.Server{
		Handler:   handler,
		TLSConfig: tlsConfig(t),
	}
	go httpsServer.ServeTLS(httpsLn, "", "")
	defer httpsServer.Close()

	a := newALPNTestDialer(t, client, server.Public())
	var dials int
	a.Dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials++
		return stdDialer.DialContext(ctx, network, addr)
	}
	u := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort("localhost", strconv.Itoa(httpsLn.Addr().(*net.TCPAddr).Port)),
		Path:   serverUpgradePath,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := a.dialURL(ctx, u, netip.Addr{}, "")
	if err != nil {
		t.Fatalf("dialURL: %v", err)
	}
	defer conn.Close()

	if peer := conn.Peer(); peer != server.Public() {
		t.Fatalf("client got peer %v; want %v", peer, server.Public())
	}

	// The fallback must happen over the same TCP connection, not a redial.
	if dials != 1 {
		t.Errorf("made %d TCP dials; want 1 (in-connection fallback)", dials)
	}

	testALPNRoundTrip(t, conn, results, false)
}

// TestALPNHandshakeEncoding verifies that the encoded handshake round-trips
// and fits in an ALPN protocol name (max 255 bytes).
func TestALPNHandshakeEncoding(t *testing.T) {
	client, server := key.NewMachine(), key.NewMachine()
	init, _, err := controlbase.ClientDeferred(client, server.Public(), 1)
	if err != nil {
		t.Fatal(err)
	}
	enc := controlhttpcommon.EncodeALPNHandshake(init)
	if len(enc) > 255 {
		t.Errorf("encoded ALPN entry is %d bytes; must be <= 255", len(enc))
	}
	got, ok := controlhttpcommon.DecodeALPNHandshake([]string{"http/1.1", enc})
	if !ok {
		t.Fatal("DecodeALPNHandshake failed")
	}
	if !bytes.Equal(got, init) {
		t.Errorf("decoded handshake doesn't match original")
	}
}
