// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/net/memnet"
)

func echoConnOnce(conn net.Conn) {
	defer conn.Close()

	b := make([]byte, 256)
	n, err := conn.Read(b)
	if err != nil {
		return
	}

	if _, err := conn.Write(b[:n]); err != nil {
		return
	}
}

func TestTCPRoundRobinHandler(t *testing.T) {
	h := tcpRoundRobinHandler{
		To: []string{"yeet.com"},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network != "tcp" {
				t.Errorf("network = %s, want %s", network, "tcp")
			}
			if addr != "yeet.com:22" {
				t.Errorf("addr = %s, want %s", addr, "yeet.com:22")
			}

			c, s := memnet.NewConn("outbound", 1024)
			go echoConnOnce(s)
			return c, nil
		},
	}

	cSock, sSock := memnet.NewTCPConn(netip.MustParseAddrPort("10.64.1.2:22"), netip.MustParseAddrPort("10.64.1.2:22"), 1024)
	h.Handle(sSock)

	// Test data write and read, the other end will echo back
	// a single stanza
	want := "hello"
	if _, err := io.WriteString(cSock, want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadAtLeast(cSock, got, len(got)); err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}

	// The other end closed the socket after the first echo, so
	// any following read should error.
	io.WriteString(cSock, "deadass heres some data on god fr")
	if _, err := io.ReadAtLeast(cSock, got, len(got)); err == nil {
		t.Error("read succeeded on closed socket")
	}
}

// Capture of first TCP data segment for a connection to https://pkgs.tailscale.com
const tlsStart = `45000239ff1840004006f9f5c0a801f2
c726b5efcf9e01bbe803b21394e3b752
801801f641dc00000101080ade3474f2
2fb93ee71603010200010001fc030303
c3acbd19d2624765bb19af4bce03365e
1d197f5bb939cdadeff26b0f8e7a0620
295b04127b82bae46aac4ff58cffef25
eba75a4b7a6de729532c411bd9dd0d2c
00203a3a130113021303c02bc02fc02c
c030cca9cca8c013c014009c009d002f
003501000193caca0000000a000a0008
1a1a001d001700180010000e000c0268
3208687474702f312e31002b0007062a
2a03040303ff01000100000d00120010
04030804040105030805050108060601
000b00020100002300000033002b0029
1a1a000100001d0020d3c76bef062979
a812ce935cfb4dbe6b3a84dc5ba9226f
23b0f34af9d1d03b4a001b0003020002
00120000446900050003026832000000
170015000012706b67732e7461696c73
63616c652e636f6d002d000201010005
00050100000000001700003a3a000100
0015002d000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
0000290094006f0069e76f2016f963ad
38c8632d1f240cd75e00e25fdef295d4
7042b26f3a9a543b1c7dc74939d77803
20527d423ff996997bda2c6383a14f49
219eeef8a053e90a32228df37ddbe126
eccf6b085c93890d08341d819aea6111
0d909f4cd6b071d9ea40618e74588a33
90d494bbb5c3002120d5a164a16c9724
c9ef5e540d8d6f007789a7acf9f5f16f
bf6a1907a6782ed02b`

func fakeSNIHeader() []byte {
	b, err := hex.DecodeString(strings.Replace(tlsStart, "\n", "", -1))
	if err != nil {
		panic(err)
	}
	return b[0x34:] // trim IP + TCP header
}

func TestTCPSNIHandler(t *testing.T) {
	h := tcpSNIHandler{
		Allowlist: []string{"pkgs.tailscale.com"},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network != "tcp" {
				t.Errorf("network = %s, want %s", network, "tcp")
			}
			if addr != "pkgs.tailscale.com:443" {
				t.Errorf("addr = %s, want %s", addr, "pkgs.tailscale.com:443")
			}

			c, s := memnet.NewConn("outbound", 1024)
			go echoConnOnce(s)
			return c, nil
		},
	}

	cSock, sSock := memnet.NewTCPConn(netip.MustParseAddrPort("10.64.1.2:22"), netip.MustParseAddrPort("10.64.1.2:443"), 1024)
	h.Handle(sSock)

	// Fake a TLS handshake record with an SNI in it.
	if _, err := cSock.Write(fakeSNIHeader()); err != nil {
		t.Fatal(err)
	}

	// Test read, the other end will echo back
	// a single stanza, which is at least the beginning of the SNI header.
	want := fakeSNIHeader()[:5]
	if _, err := cSock.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadAtLeast(cSock, got, len(got)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
