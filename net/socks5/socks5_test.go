// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package socks5

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

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

	// make a socks5 udpAssociate conn
	newUdpAssociateConn := func() (socks5Conn net.Conn, socks5UDPAddr socksAddr) {
		// net/proxy don't support UDP, so we need to manually send the SOCKS5 UDP request
		conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", socks5Port))
		if err != nil {
			t.Fatal(err)
		}
		_, err = conn.Write([]byte{socks5Version, 0x01, noAuthRequired}) // client hello with no auth
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1024)
		n, err := conn.Read(buf) // server hello
		if err != nil {
			t.Fatal(err)
		}
		if n != 2 || buf[0] != socks5Version || buf[1] != noAuthRequired {
			t.Fatalf("got: %q want: 0x05 0x00", buf[:n])
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

		n, err = conn.Read(buf) // server response
		if err != nil {
			t.Fatal(err)
		}
		if n < 3 || !bytes.Equal(buf[:3], []byte{socks5Version, 0x00, 0x00}) {
			t.Fatalf("got: %q want: 0x05 0x00 0x00", buf[:n])
		}
		udpProxySocksAddr, err := parseSocksAddr(bytes.NewReader(buf[3:n]))
		if err != nil {
			t.Fatal(err)
		}

		return conn, udpProxySocksAddr
	}

	conn, udpProxySocksAddr := newUdpAssociateConn()
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

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", socks5Port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{socks5Version, 0x01, noAuthRequired}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || buf[0] != socks5Version || buf[1] != noAuthRequired {
		t.Fatalf("got %q, want 0x05 0x00", buf[:n])
	}
	targetAddrPkt, err := socksAddr{addrType: ipv4, addr: "0.0.0.0", port: 0}.marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(append([]byte{socks5Version, byte(udpAssociate), 0x00}, targetAddrPkt...)); err != nil {
		t.Fatal(err)
	}
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n < 3 || !bytes.Equal(buf[:3], []byte{socks5Version, 0x00, 0x00}) {
		t.Fatalf("got %q, want 0x05 0x00 0x00", buf[:n])
	}
	udpProxySocksAddr, err := parseSocksAddr(bytes.NewReader(buf[3:n]))
	if err != nil {
		t.Fatal(err)
	}

	udpProxyAddr, err := net.ResolveUDPAddr("udp", udpProxySocksAddr.hostPort())
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.DialUDP("udp", nil, udpProxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	// Drain responses so the target->client goroutines keep writing.
	var (
		wg       sync.WaitGroup
		gotReply int // written by the drain goroutine, read after wg.Wait
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		rbuf := make([]byte, 1024)
		for {
			if _, err := udpConn.Read(rbuf); err != nil {
				return
			}
			gotReply++
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

	udpConn.Close()
	wg.Wait()

	// UDP is lossy, so don't require every reply. One reply is enough to show
	// the proxy relayed something.
	if gotReply == 0 {
		t.Error("got no responses back through the proxy")
	}
}
