// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package socks5

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

type trackedTCPConn struct {
	net.Conn
	readErr     error
	readGate    <-chan struct{}
	readStarted chan struct{}
	readOnce    sync.Once
	closed      chan struct{}
	closeOnce   sync.Once
}

func newTrackedTCPConn(conn net.Conn) *trackedTCPConn {
	return &trackedTCPConn{
		Conn:        conn,
		readStarted: make(chan struct{}),
		closed:      make(chan struct{}),
	}
}

func (c *trackedTCPConn) Read(p []byte) (int, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	if c.readErr != nil {
		if c.readGate != nil {
			<-c.readGate
		}
		return 0, c.readErr
	}
	return c.Conn.Read(p)
}

func (c *trackedTCPConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

type closeWriteTCPConn struct {
	*trackedTCPConn
	closeWriteErr error
}

func (c *closeWriteTCPConn) CloseWrite() error {
	if c.closeWriteErr != nil {
		return c.closeWriteErr
	}
	return c.Conn.(*net.TCPConn).CloseWrite()
}

type writeErrorTCPConn struct {
	*trackedTCPConn
	writeErr error
}

func (c *writeErrorTCPConn) Write([]byte) (int, error) { return 0, c.writeErr }

func tcpConnPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn.(*net.TCPConn)
	}()
	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case conn := <-accepted:
		return dialed.(*net.TCPConn), conn
	case err := <-acceptErr:
		dialed.Close()
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		dialed.Close()
		t.Fatal("timed out accepting TCP test connection")
	}
	return nil, nil
}

func readConnectResponse(t *testing.T, conn net.Conn) {
	t.Helper()
	var header [3]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if header != [3]byte{socks5Version, byte(success), 0} {
		t.Fatalf("CONNECT response = %x, want 050000", header)
	}
	if _, err := parseSocksAddr(conn); err != nil {
		t.Fatalf("parse CONNECT bind address: %v", err)
	}
}

func dialSOCKSTCP(t *testing.T, socksServer string, target netip.AddrPort) *net.TCPConn {
	t.Helper()
	connRaw, err := net.Dial("tcp", socksServer)
	if err != nil {
		t.Fatal(err)
	}
	conn := connRaw.(*net.TCPConn)
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{socks5Version, 1, noAuthRequired}); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if greeting != [2]byte{socks5Version, noAuthRequired} {
		conn.Close()
		t.Fatalf("greeting = %x, want 0500", greeting)
	}
	targetAddr := socksAddr{addrType: ipv4, addr: target.Addr().String(), port: uint16(target.Port())}
	targetBytes, err := targetAddr.marshal()
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if _, err := conn.Write(append([]byte{socks5Version, byte(connect), 0}, targetBytes...)); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	readConnectResponse(t, conn)
	return conn
}

func TestTCPHalfCloseReturnsCompleteResponse(t *testing.T) {
	const (
		requestSize  = 8 << 20
		responseSize = 1 << 20
	)
	request := bytes.Repeat([]byte("socks5-request-"), requestSize/len("socks5-request-")+1)[:requestSize]
	response := bytes.Repeat([]byte("socks5-response-"), responseSize/len("socks5-response-")+1)[:responseSize]
	wantRequestDigest := sha256.Sum256(request)
	wantResponseDigest := sha256.Sum256(response)

	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { backendListener.Close() })

	type backendResult struct {
		bytes  int
		digest [sha256.Size]byte
		err    error
	}
	backendEOF := make(chan backendResult, 1)
	backendDone := make(chan error, 1)
	go func() {
		conn, err := backendListener.Accept()
		if err != nil {
			backendDone <- err
			return
		}
		defer conn.Close()
		got, err := io.ReadAll(conn)
		backendEOF <- backendResult{bytes: len(got), digest: sha256.Sum256(got), err: err}
		if err == nil {
			_, err = conn.Write(response)
		}
		if err == nil {
			err = conn.(*net.TCPConn).CloseWrite()
		}
		backendDone <- err
	}()

	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socksListener.Close() })
	server := &Server{Logf: t.Logf}
	go server.Serve(socksListener)

	clientRaw, err := net.Dial("tcp", socksListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := clientRaw.(*net.TCPConn)
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte{socks5Version, 1, noAuthRequired}); err != nil {
		t.Fatal(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(client, greeting[:]); err != nil {
		t.Fatal(err)
	}
	if greeting != [2]byte{socks5Version, noAuthRequired} {
		t.Fatalf("greeting = %x, want 0500", greeting)
	}
	backendAddr := backendListener.Addr().(*net.TCPAddr).AddrPort()
	target := socksAddr{addrType: ipv4, addr: backendAddr.Addr().String(), port: uint16(backendAddr.Port())}
	targetBytes, err := target.marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(append([]byte{socks5Version, byte(connect), 0}, targetBytes...)); err != nil {
		t.Fatal(err)
	}
	var responseHeader [3]byte
	if _, err := io.ReadFull(client, responseHeader[:]); err != nil {
		t.Fatal(err)
	}
	if responseHeader != [3]byte{socks5Version, byte(success), 0} {
		t.Fatalf("CONNECT response = %x, want 050000", responseHeader)
	}
	if _, err := parseSocksAddr(client); err != nil {
		t.Fatalf("parse CONNECT bind address: %v", err)
	}

	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	gotBackend := <-backendEOF
	if gotBackend.err != nil {
		t.Fatalf("backend read: %v", gotBackend.err)
	}
	if gotBackend.bytes != requestSize || gotBackend.digest != wantRequestDigest {
		t.Fatalf("backend request = %d bytes/%x, want %d bytes/%x", gotBackend.bytes, gotBackend.digest, requestSize, wantRequestDigest)
	}
	gotResponse, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("client read response and final EOF: %v", err)
	}
	if len(gotResponse) != responseSize || sha256.Sum256(gotResponse) != wantResponseDigest {
		t.Fatalf("client response = %d bytes/%x, want %d bytes/%x", len(gotResponse), sha256.Sum256(gotResponse), responseSize, wantResponseDigest)
	}
	if err := <-backendDone; err != nil {
		t.Fatalf("backend response: %v", err)
	}
}

func TestTCPPumpFailureClosesBothAndWaits(t *testing.T) {
	errCopy := errors.New("injected copy error")
	errCloseWrite := errors.New("injected CloseWrite error")
	tests := []struct {
		name               string
		clientUnsupported  bool
		backendUnsupported bool
		clientReadErr      error
		backendReadErr     error
		clientCloseWrite   error
		backendCloseWrite  error
		clientEOF          bool
		backendEOF         bool
		want               error
	}{
		{name: "client CloseWrite unsupported", clientUnsupported: true, backendEOF: true, want: errors.ErrUnsupported},
		{name: "backend CloseWrite unsupported", backendUnsupported: true, clientEOF: true, want: errors.ErrUnsupported},
		{name: "client copy error", clientReadErr: errCopy, want: errCopy},
		{name: "backend copy error", backendReadErr: errCopy, want: errCopy},
		{name: "client CloseWrite error", clientCloseWrite: errCloseWrite, backendEOF: true, want: errCloseWrite},
		{name: "backend CloseWrite error", backendCloseWrite: errCloseWrite, clientEOF: true, want: errCloseWrite},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientPeer, clientRaw := tcpConnPair(t)
			backendRaw, backendPeer := tcpConnPair(t)
			defer clientPeer.Close()
			defer backendPeer.Close()

			clientTrack := newTrackedTCPConn(clientRaw)
			backendTrack := newTrackedTCPConn(backendRaw)
			readGate := make(chan struct{})
			clientTrack.readErr, clientTrack.readGate = tt.clientReadErr, readGate
			backendTrack.readErr, backendTrack.readGate = tt.backendReadErr, readGate

			var clientConn net.Conn = &closeWriteTCPConn{trackedTCPConn: clientTrack, closeWriteErr: tt.clientCloseWrite}
			if tt.clientUnsupported {
				clientConn = clientTrack
			}
			var backendConn net.Conn = &closeWriteTCPConn{trackedTCPConn: backendTrack, closeWriteErr: tt.backendCloseWrite}
			if tt.backendUnsupported {
				backendConn = backendTrack
			}

			conn := &Conn{
				clientConn: clientConn,
				request:    &request{destination: socksAddr{addrType: ipv4, addr: "127.0.0.1", port: 1}},
				srv: &Server{Dialer: func(context.Context, string, string) (net.Conn, error) {
					return backendConn, nil
				}},
			}
			done := make(chan error, 1)
			go func() { done <- conn.handleTCP() }()
			readConnectResponse(t, clientPeer)

			if tt.clientReadErr != nil || tt.backendReadErr != nil {
				close(readGate)
			}
			if tt.clientEOF {
				if err := clientPeer.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			}
			if tt.backendEOF {
				if err := backendPeer.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			}

			select {
			case err := <-done:
				if !errors.Is(err, tt.want) {
					t.Fatalf("handleTCP error = %v, want %v", err, tt.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("handleTCP did not unblock and wait for both pumps")
			}
			for name, closed := range map[string]<-chan struct{}{
				"client":  clientTrack.closed,
				"backend": backendTrack.closed,
			} {
				select {
				case <-closed:
				default:
					t.Errorf("%s connection was not fully closed", name)
				}
			}
		})
	}
}

func TestTCPConnectResponseWriteFailureClosesBeforePumps(t *testing.T) {
	errWrite := errors.New("injected CONNECT response write error")
	clientPeer, clientRaw := tcpConnPair(t)
	backendRaw, backendPeer := tcpConnPair(t)
	defer clientPeer.Close()
	defer backendPeer.Close()
	clientTrack := newTrackedTCPConn(clientRaw)
	backendTrack := newTrackedTCPConn(backendRaw)
	conn := &Conn{
		clientConn: &writeErrorTCPConn{trackedTCPConn: clientTrack, writeErr: errWrite},
		request:    &request{destination: socksAddr{addrType: ipv4, addr: "127.0.0.1", port: 1}},
		srv: &Server{Dialer: func(context.Context, string, string) (net.Conn, error) {
			return &closeWriteTCPConn{trackedTCPConn: backendTrack}, nil
		}},
	}
	if err := conn.handleTCP(); !errors.Is(err, errWrite) {
		t.Fatalf("handleTCP error = %v, want %v", err, errWrite)
	}
	for name, tracked := range map[string]*trackedTCPConn{"client": clientTrack, "backend": backendTrack} {
		select {
		case <-tracked.closed:
		default:
			t.Errorf("%s connection was not fully closed", name)
		}
		select {
		case <-tracked.readStarted:
			t.Errorf("%s pump started before CONNECT response succeeded", name)
		default:
		}
	}
}

func TestTCPResetIsConnectionLocal(t *testing.T) {
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendListener.Close()
	backendAddr := backendListener.Addr().(*net.TCPAddr).AddrPort()
	seen := map[byte]chan struct{}{
		'B': make(chan struct{}),
		'S': make(chan struct{}),
		'N': make(chan struct{}),
	}
	brokenClosed := make(chan struct{})
	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var id [1]byte
				if _, err := io.ReadFull(conn, id[:]); err != nil {
					return
				}
				if event := seen[id[0]]; event != nil {
					close(event)
				}
				if id[0] == 'B' {
					io.Copy(io.Discard, conn)
					close(brokenClosed)
					return
				}
				if _, err := conn.Write(id[:]); err != nil {
					return
				}
				io.Copy(conn, conn)
			}()
		}
	}()

	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socksListener.Close()
	server := &Server{Logf: func(string, ...any) {}}
	go server.Serve(socksListener)

	sibling := dialSOCKSTCP(t, socksListener.Addr().String(), backendAddr)
	defer sibling.Close()
	if _, err := sibling.Write([]byte{'S'}); err != nil {
		t.Fatal(err)
	}
	<-seen['S']
	var got [1]byte
	if _, err := io.ReadFull(sibling, got[:]); err != nil || got[0] != 'S' {
		t.Fatalf("initial sibling echo = %q, %v", got, err)
	}

	broken := dialSOCKSTCP(t, socksListener.Addr().String(), backendAddr)
	if _, err := broken.Write([]byte{'B'}); err != nil {
		t.Fatal(err)
	}
	<-seen['B']
	if err := broken.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err := broken.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-brokenClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("reset connection was not reaped")
	}

	if _, err := sibling.Write([]byte{'X'}); err != nil {
		t.Fatalf("sibling write after reset: %v", err)
	}
	if _, err := io.ReadFull(sibling, got[:]); err != nil || got[0] != 'X' {
		t.Fatalf("sibling echo after reset = %q, %v", got, err)
	}

	next := dialSOCKSTCP(t, socksListener.Addr().String(), backendAddr)
	defer next.Close()
	if _, err := next.Write([]byte{'N'}); err != nil {
		t.Fatal(err)
	}
	<-seen['N']
	if _, err := io.ReadFull(next, got[:]); err != nil || got[0] != 'N' {
		t.Fatalf("subsequent connection echo = %q, %v", got, err)
	}
}

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
