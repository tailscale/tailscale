// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package socks5

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func socks5Server(listener net.Listener) {
	var server Server
	err := server.Serve(listener)
	if err != nil {
		panic(err)
	}
	listener.Close()
}

func backendServer(listener net.Listener) {
	conn, err := listener.Accept()
	if err != nil {
		panic(err)
	}
	conn.Write([]byte("Test"))
	conn.Close()
	listener.Close()
}

func udpEchoServer(conn net.PacketConn) {
	var buf [1024]byte
	n, addr, err := conn.ReadFrom(buf[:])
	if err != nil {
		panic(err)
	}
	_, err = conn.WriteTo(buf[:n], addr)
	if err != nil {
		panic(err)
	}
	conn.Close()
}

func TestRead(t *testing.T) {
	// backend server which we'll use SOCKS5 to connect to
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	backendServerPort := listener.Addr().(*net.TCPAddr).Port
	go backendServer(listener)

	// SOCKS5 server
	socks5, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	socks5Port := socks5.Addr().(*net.TCPAddr).Port
	go socks5Server(socks5)

	addr := fmt.Sprintf("localhost:%d", socks5Port)
	socksDialer, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	addr = fmt.Sprintf("localhost:%d", backendServerPort)
	conn, err := socksDialer.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf) != "Test" {
		t.Fatalf("got: %q want: Test", buf)
	}

	err = conn.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadPassword(t *testing.T) {
	// backend server which we'll use SOCKS5 to connect to
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	backendServerPort := ln.Addr().(*net.TCPAddr).Port
	go backendServer(ln)

	socks5ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		socks5ln.Close()
	})
	auth := &proxy.Auth{User: "foo", Password: "bar"}
	go func() {
		s := Server{Username: auth.User, Password: auth.Password}
		err := s.Serve(socks5ln)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			panic(err)
		}
	}()

	addr := fmt.Sprintf("localhost:%d", socks5ln.Addr().(*net.TCPAddr).Port)

	if d, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct); err != nil {
		t.Fatal(err)
	} else {
		if _, err := d.Dial("tcp", addr); err == nil {
			t.Fatal("expected no-auth dial error")
		}
	}

	badPwd := &proxy.Auth{User: "foo", Password: "not right"}
	if d, err := proxy.SOCKS5("tcp", addr, badPwd, proxy.Direct); err != nil {
		t.Fatal(err)
	} else {
		if _, err := d.Dial("tcp", addr); err == nil {
			t.Fatal("expected bad password dial error")
		}
	}

	badUsr := &proxy.Auth{User: "not right", Password: "bar"}
	if d, err := proxy.SOCKS5("tcp", addr, badUsr, proxy.Direct); err != nil {
		t.Fatal(err)
	} else {
		if _, err := d.Dial("tcp", addr); err == nil {
			t.Fatal("expected bad username dial error")
		}
	}

	socksDialer, err := proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	addr = fmt.Sprintf("localhost:%d", backendServerPort)
	conn, err := socksDialer.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "Test" {
		t.Fatalf("got: %q want: Test", buf)
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

// newUDPAssociateConn opens a SOCKS5 connection to the server on socks5Port
// and completes a UDP ASSOCIATE handshake on it. It returns the TCP control
// connection and the address of the server's UDP relay.
func newUDPAssociateConn(t *testing.T, socks5Port int) (socks5Conn net.Conn, socks5UDPAddr socksAddr) {
	t.Helper()

	// net/proxy doesn't support UDP, so we need to manually send the SOCKS5 UDP request
	conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", socks5Port))
	if err != nil {
		t.Fatal(err)
	}
	// Close the control connection even when the handshake below fails, since
	// a t.Fatal here skips the caller's own close.
	t.Cleanup(func() { conn.Close() })

	_, err = conn.Write([]byte{socks5Version, 0x01, noAuthRequired}) // client hello with no auth
	if err != nil {
		t.Fatal(err)
	}
	var buf [3]byte
	if _, err := io.ReadFull(conn, buf[:2]); err != nil { // server hello
		t.Fatal(err)
	}
	if buf[0] != socks5Version || buf[1] != noAuthRequired {
		t.Fatalf("got: %q want: 0x05 0x00", buf[:2])
	}

	targetAddr := socksAddr{addrType: ipv4, addr: "0.0.0.0", port: 0}
	targetAddrPkt, err := targetAddr.marshal()
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Write(append([]byte{socks5Version, byte(udpAssociate), 0x00}, targetAddrPkt...)) // client request
	if err != nil {
		t.Fatal(err)
	}

	// The bind address that follows the header is variable length, so parse it
	// straight from the connection rather than from a fixed-size read.
	if _, err := io.ReadFull(conn, buf[:3]); err != nil { // server response header
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:3], []byte{socks5Version, 0x00, 0x00}) {
		t.Fatalf("got: %q want: 0x05 0x00 0x00", buf[:3])
	}
	udpProxySocksAddr, err := parseSocksAddr(conn)
	if err != nil {
		t.Fatal(err)
	}

	return conn, udpProxySocksAddr
}

func TestUDP(t *testing.T) {
	// backend UDP server which we'll use SOCKS5 to connect to
	newUDPEchoServer := func() net.PacketConn {
		listener, err := net.ListenPacket("udp", ":0")
		if err != nil {
			t.Fatal(err)
		}
		go udpEchoServer(listener)
		return listener
	}

	const echoServerNumber = 3
	echoServerListener := make([]net.PacketConn, echoServerNumber)
	for i := range echoServerNumber {
		echoServerListener[i] = newUDPEchoServer()
	}
	defer func() {
		for i := range echoServerNumber {
			_ = echoServerListener[i].Close()
		}
	}()

	// SOCKS5 server
	socks5, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	socks5Port := socks5.Addr().(*net.TCPAddr).Port
	go socks5Server(socks5)

	conn, udpProxySocksAddr := newUDPAssociateConn(t, socks5Port)
	defer conn.Close()

	sendUDPAndWaitResponse := func(socks5UDPConn net.Conn, addr socksAddr, body []byte) (responseBody []byte) {
		udpPayload, err := (&udpRequest{addr: addr}).marshal()
		if err != nil {
			t.Fatal(err)
		}
		udpPayload = append(udpPayload, body...)
		_, err = socks5UDPConn.Write(udpPayload)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1024)
		n, err := socks5UDPConn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		_, responseBody, err = parseUDPRequest(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		return responseBody
	}

	udpProxyAddr, err := net.ResolveUDPAddr("udp", udpProxySocksAddr.hostPort())
	if err != nil {
		t.Fatal(err)
	}
	socks5UDPConn, err := net.DialUDP("udp", nil, udpProxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer socks5UDPConn.Close()

	for i := range echoServerNumber {
		port := echoServerListener[i].LocalAddr().(*net.UDPAddr).Port
		addr := socksAddr{addrType: ipv4, addr: "127.0.0.1", port: uint16(port)}
		requestBody := fmt.Appendf(nil, "Test %d", i)
		responseBody := sendUDPAndWaitResponse(socks5UDPConn, addr, requestBody)
		if !bytes.Equal(requestBody, responseBody) {
			t.Fatalf("got: %q want: %q", responseBody, requestBody)
		}
	}
}

func udpEchoServerLoop(conn net.PacketConn) {
	var buf [1024]byte
	for {
		n, addr, err := conn.ReadFrom(buf[:])
		if err != nil {
			return
		}
		if _, err := conn.WriteTo(buf[:n], addr); err != nil {
			return
		}
	}
}

// TestUDPConcurrent keeps datagrams in flight to several targets at once so
// the client->target goroutine writes Conn.udpClientAddr while the per-target
// target->client goroutines read it.
func TestUDPConcurrent(t *testing.T) {
	const echoServerNumber = 4

	echo := make([]net.PacketConn, echoServerNumber)
	for i := range echo {
		ln, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		echo[i] = ln
		go udpEchoServerLoop(ln)
	}
	defer func() {
		for _, ln := range echo {
			ln.Close()
		}
	}()

	socks5ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socks5ln.Close()
	socks5Port := socks5ln.Addr().(*net.TCPAddr).Port
	go func() {
		var server Server
		// The response goroutines outlive the test body and log once the echo
		// servers close, so t.Logf would panic here.
		server.Logf = func(string, ...any) {}
		server.Serve(socks5ln)
	}()

	conn, udpProxySocksAddr := newUDPAssociateConn(t, socks5Port)
	defer conn.Close()

	udpProxyAddr, err := net.ResolveUDPAddr("udp", udpProxySocksAddr.hostPort())
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.DialUDP("udp", nil, udpProxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	// Drain responses so the target->client goroutines keep writing. The drain
	// goroutine closes replied once it has seen a response come back.
	var wg sync.WaitGroup
	replied := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		rbuf := make([]byte, 1024)
		var n int
		for {
			if _, err := udpConn.Read(rbuf); err != nil {
				return
			}
			n++
			if n == 1 {
				close(replied)
			}
		}
	}()

	const rounds = 200
	for range rounds {
		for i := range echo {
			port := echo[i].LocalAddr().(*net.UDPAddr).Port
			addr := socksAddr{addrType: ipv4, addr: "127.0.0.1", port: uint16(port)}
			pkt, err := (&udpRequest{addr: addr}).marshal()
			if err != nil {
				t.Fatal(err)
			}
			pkt = fmt.Appendf(pkt, "Test %d", i)
			if _, err := udpConn.Write(pkt); err != nil {
				t.Fatal(err)
			}
		}
	}

	// UDP is lossy, so don't require every reply. One reply is enough to show
	// the proxy relayed something. Wait for it before closing the connection.
	// With GOMAXPROCS=1 the whole send loop can finish before the proxy's relay
	// goroutines run at all, so closing right away drops every response.
	//
	// A reply arrives within about 20ms locally. The timeout sits above the
	// relay's own readTimeout so that a stuck read there gets one full retry
	// before this test gives up.
	select {
	case <-replied:
	case <-time.After(10 * time.Second):
		t.Error("timed out waiting for a response back through the proxy")
	}

	udpConn.Close()
	wg.Wait()
}

// syncBuffer is a bytes.Buffer that is safe for concurrent use.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestUDPLogNilLogf checks that a UDP error path logs through the standard
// logger when Server.Logf is nil. It used to panic instead, because Conn kept
// its own copy of the nil Server.Logf and called it without a fallback.
func TestUDPLogNilLogf(t *testing.T) {
	var logs syncBuffer
	oldOut := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldOut) })

	socks5, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socks5.Close() })
	socks5Port := socks5.Addr().(*net.TCPAddr).Port
	go func() {
		var server Server // Logf stays nil, which is what this test exercises
		err := server.Serve(socks5)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			panic(err)
		}
	}()

	conn, udpProxySocksAddr := newUDPAssociateConn(t, socks5Port)
	defer conn.Close()

	udpProxyAddr, err := net.ResolveUDPAddr("udp", udpProxySocksAddr.hostPort())
	if err != nil {
		t.Fatal(err)
	}
	socks5UDPConn, err := net.DialUDP("udp", nil, udpProxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer socks5UDPConn.Close()

	// This datagram is too short to be a SOCKS5 UDP request, so the server
	// fails to parse it and logs the failure.
	if _, err := socks5UDPConn.Write([]byte{0x00}); err != nil {
		t.Fatal(err)
	}

	const want = "handle udp request fail"
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(logs.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("log output %q does not contain %q", logs.String(), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// runOneTCPConn accepts one connection on ln and runs it through a SOCKS5
// [Conn] of srv, returning a channel that receives the result of [Conn.Run]
// once the proxied connection has fully closed in both directions.
func runOneTCPConn(t *testing.T, ln net.Listener, srv *Server) <-chan error {
	if srv.Logf == nil {
		srv.Logf = t.Logf
	}
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer c.Close()
		errc <- (&Conn{clientConn: c, srv: srv}).Run()
	}()
	return errc
}

// dialViaSOCKS5 connects to addr through the SOCKS5 server at socks5Addr.
func dialViaSOCKS5(t *testing.T, socks5Addr, addr string) *net.TCPConn {
	socksDialer, err := proxy.SOCKS5("tcp", socks5Addr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := socksDialer.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn.(*net.TCPConn)
}

// TestTCPHalfClose checks that a half-close in either direction propagates
// through the proxy: the backend sees EOF after the client's CloseWrite but
// can still reply, and the client sees the reply followed by EOF once the
// backend closes.
func TestTCPHalfClose(t *testing.T) {
	const msg = "we are so winning"

	// Backend server which we'll use SOCKS5 to connect to. It reads the
	// request until EOF, then replies and closes.
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		c, err := listener.Accept()
		if err != nil {
			t.Errorf("backend accept conn: %v", err)
			return
		}
		defer c.Close()
		got, err := io.ReadAll(c)
		if err != nil {
			t.Errorf("backend read: %v", err)
		}
		if string(got) != msg {
			t.Errorf("backend read: want %q, got %q", msg, got)
		}
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Errorf("backend write: %v", err)
		}
	}()

	socks5, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socks5.Close()
	runErr := runOneTCPConn(t, socks5, &Server{})

	conn := dialViaSOCKS5(t, socks5.Addr().String(), listener.Addr().String())
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("client closewrite: %v", err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Errorf("client read: %v", err)
	}
	if string(got) != msg {
		t.Errorf("client read: want %q, got %q", msg, got)
	}
	<-backendDone

	// A cleanly half-closed connection in each direction is not an error.
	// It used to be reported as one on macOS, where shutting down the read
	// side of a socket that has already received a FIN fails with ENOTCONN.
	if err := <-runErr; err != nil {
		t.Errorf("Conn.Run: %v", err)
	}
}

// TestTCPBackendReset checks that when the backend resets the connection,
// the proxy tears down the client connection too rather than leaving it
// half-open until the client happens to close it.
func TestTCPBackendReset(t *testing.T) {
	const msg = "hello"

	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		c, err := listener.Accept()
		if err != nil {
			t.Errorf("backend accept conn: %v", err)
			return
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Errorf("backend read: %v", err)
		}
		// Close with SO_LINGER zero so the kernel sends a RST rather
		// than a FIN.
		c.(*net.TCPConn).SetLinger(0)
		c.Close()
	}()

	socks5, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socks5.Close()
	runErr := runOneTCPConn(t, socks5, &Server{})

	conn := dialViaSOCKS5(t, socks5.Addr().String(), listener.Addr().String())
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("client write: %v", err)
	}

	// The client never closes its side. The proxy must still finish once
	// the backend is gone, and report why.
	select {
	case err := <-runErr:
		if err == nil {
			t.Errorf("Conn.Run returned nil, want a backend error")
		} else {
			t.Logf("Conn.Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for the proxy to give up on the client connection")
	}
	var buf [1]byte
	if n, err := conn.Read(buf[:]); err == nil {
		t.Errorf("client read got %d bytes and no error, want EOF or reset", n)
	}
}

// resetBackend is a fake backend connection for [TestTCPBackendResetMidResponse].
// It behaves like a TCP connection whose peer replied and then reset the
// connection: reads return the reply and then ECONNRESET, and writes fail
// immediately. The first failed write closes writeFailed.
type resetBackend struct {
	reply       *bytes.Reader
	writeFailed chan struct{}
	failOnce    sync.Once

	mu     sync.Mutex
	closed bool
}

func (b *resetBackend) Read(p []byte) (int, error) {
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	n, err := b.reply.Read(p)
	if err == io.EOF {
		err = syscall.ECONNRESET
	}
	return n, err
}

func (b *resetBackend) Write(p []byte) (int, error) {
	b.failOnce.Do(func() { close(b.writeFailed) })
	return 0, syscall.EPIPE
}

func (b *resetBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return nil
}

func (b *resetBackend) CloseRead() error    { return nil }
func (b *resetBackend) CloseWrite() error   { return syscall.ENOTCONN }
func (b *resetBackend) LocalAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }
func (b *resetBackend) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}
}
func (b *resetBackend) SetDeadline(time.Time) error      { return nil }
func (b *resetBackend) SetReadDeadline(time.Time) error  { return nil }
func (b *resetBackend) SetWriteDeadline(time.Time) error { return nil }

// TestTCPBackendResetMidResponse checks that when the backend replies and
// then resets the connection while the client is still sending, the whole
// reply still reaches the client. The proxy must let the backend-to-client
// direction drain what the backend sent before the reset rather than closing
// the backend connection as soon as the client-to-backend direction fails.
//
// The backend is faked so that the ordering is deterministic: its writes
// fail at once, while its reads still have a reply too large to fit in the
// socket buffers between the proxy and the client.
func TestTCPBackendResetMidResponse(t *testing.T) {
	reply := bytes.Repeat([]byte("r"), 16<<20)
	backend := &resetBackend{
		reply:       bytes.NewReader(reply),
		writeFailed: make(chan struct{}),
	}
	srv := &Server{
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			return backend, nil
		},
	}

	socks5, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socks5.Close()
	runErr := runOneTCPConn(t, socks5, srv)

	conn := dialViaSOCKS5(t, socks5.Addr().String(), "backend.invalid:80")
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}

	// Don't read the reply until the proxy has failed to forward the
	// client's write, so that most of the reply is still inside the proxy
	// at that point.
	select {
	case <-backend.writeFailed:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for the proxy to write to the backend")
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Errorf("client read: %v", err)
	}
	if len(got) != len(reply) {
		t.Errorf("client read %d bytes of the reply, want %d", len(got), len(reply))
	} else if !bytes.Equal(got, reply) {
		t.Errorf("client read a corrupted reply")
	}

	select {
	case err := <-runErr:
		if err == nil {
			t.Errorf("Conn.Run returned nil, want a backend error")
		} else {
			t.Logf("Conn.Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for Conn.Run")
	}
}
