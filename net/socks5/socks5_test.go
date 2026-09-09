// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package socks5

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
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
