// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix || windows

package netstack

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/proxymap"
)

// addrPortUnmap returns ap with a 4-in-6 address unmapped to its 4-byte
// form, matching how registrations are keyed.
func addrPortUnmap(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// TestDialTCPRegisterLocal verifies that the identity registration for a
// forwarded connection's backend local address exists before the kernel
// completes the TCP handshake, so a backend that WhoIses its peer
// immediately after Accept always finds the mapping (issue #1616).
func TestDialTCPRegisterLocal(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			listenAddr := "127.0.0.1:0"
			if network == "tcp6" {
				listenAddr = "[::1]:0"
			}
			ln, err := net.Listen(network, listenAddr)
			if err != nil {
				t.Skipf("listen %s: %v", network, err)
			}
			defer ln.Close()

			var pm proxymap.Mapper
			clientIP := netip.MustParseAddr("100.64.1.23")

			type whoisResult struct {
				remote netip.AddrPort
				ip     netip.Addr
				ok     bool
			}
			results := make(chan whoisResult, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				// Look up the peer identity the instant the connection is
				// accepted, before any bytes flow, like a localhost server
				// identifying its caller.
				remote := addrPortUnmap(conn.RemoteAddr().(*net.TCPAddr).AddrPort())
				ip, ok := pm.WhoIsIPPort("tcp", remote)
				results <- whoisResult{remote, ip, ok}
				io.Copy(io.Discard, conn) // wait for the client to close
			}()

			dst := addrPortUnmap(ln.Addr().(*net.TCPAddr).AddrPort())
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, local, err := dialTCPRegisterLocal(ctx, dst, &pm, clientIP)
			if err != nil {
				t.Fatalf("dialTCPRegisterLocal: %v", err)
			}
			defer conn.Close()
			if !local.IsValid() || local.Port() == 0 {
				t.Fatalf("dialTCPRegisterLocal returned invalid local address %v", local)
			}
			if got := addrPortUnmap(conn.LocalAddr().(*net.TCPAddr).AddrPort()); got != local {
				t.Fatalf("reported local address %v does not match connection local address %v", local, got)
			}
			// The registration must already be visible when the dial
			// returns; it was created before the connect was issued.
			if ip, ok := pm.WhoIsIPPort("tcp", local); !ok || ip != clientIP {
				t.Fatalf("WhoIsIPPort(%v) = %v, %v; want %v, true", local, ip, ok, clientIP)
			}

			select {
			case res := <-results:
				if res.remote != local {
					t.Fatalf("backend saw remote address %v; want registered local address %v", res.remote, local)
				}
				if !res.ok {
					t.Fatalf("backend WhoIsIPPort(%v) found no identity at accept time; registration raced the handshake (issue #1616)", res.remote)
				}
				if res.ip != clientIP {
					t.Fatalf("backend WhoIsIPPort(%v) = %v; want %v", res.remote, res.ip, clientIP)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("timed out waiting for the backend to accept")
			}

			pm.UnregisterIPPortIdentity("tcp", local)
			if _, ok := pm.WhoIsIPPort("tcp", local); ok {
				t.Fatalf("WhoIsIPPort(%v) still present after unregister", local)
			}
		})
	}
}

// TestDialTCPRegisterLocalConnectError verifies that a failed dial leaves no
// stale registration behind.
func TestDialTCPRegisterLocalConnectError(t *testing.T) {
	// Find a loopback port that is (almost certainly) closed by binding one
	// and immediately releasing it.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dst := addrPortUnmap(ln.Addr().(*net.TCPAddr).AddrPort())
	ln.Close()

	var pm proxymap.Mapper
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _, err = dialTCPRegisterLocal(ctx, dst, &pm, netip.MustParseAddr("100.64.1.23"))
	if err == nil {
		t.Fatal("dialTCPRegisterLocal to a closed port succeeded; want connection refused")
	}
	if got := pm.String(); got != "no mappings" {
		t.Fatalf("failed dial left registrations behind: %v", got)
	}
}

// TestDialTCPRegisterLocalRejectsNonLoopback verifies the helper refuses
// non-loopback destinations, where pre-binding a source address would not
// be identity-preserving.
func TestDialTCPRegisterLocalRejectsNonLoopback(t *testing.T) {
	var pm proxymap.Mapper
	_, _, err := dialTCPRegisterLocal(context.Background(), netip.MustParseAddrPort("192.0.2.1:80"), &pm, netip.MustParseAddr("100.64.1.23"))
	if err == nil {
		t.Fatal("dialTCPRegisterLocal accepted a non-loopback destination")
	}
}
