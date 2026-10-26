// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestFwdDialRelayLifecycle checks that the extra socketpair preserves
// half-closes in both directions, and that monitor teardown closes an idle
// service connection even while the relay is waiting for traffic.
func TestFwdDialRelayLifecycle(t *testing.T) {
	for _, mode := range []string{"client-half-close", "service-half-close", "monitor-close"} {
		t.Run(mode, func(t *testing.T) {
			mc := startFwdTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))
			dir := fwdWritableDir(t, os.Getuid(), os.Getgid())
			path := filepath.Join(dir, "relay.sock")
			ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			if err := ln.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := testCtx()
			defer cancel()
			client, err := mc.Dial(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			service, err := ln.AcceptUnix()
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			for _, c := range []net.Conn{client, service} {
				if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			readEOF := func(c net.Conn, want string) {
				t.Helper()
				got, err := io.ReadAll(c)
				if err != nil || string(got) != want {
					t.Fatalf("read to EOF = %q, %v; want %q, nil", got, err, want)
				}
			}
			if mode == "monitor-close" {
				if err := mc.Close(); err != nil {
					t.Fatal(err)
				}
				readEOF(service, "")
				readEOF(client, "")
				return
			}

			var first, second interface {
				net.Conn
				CloseWrite() error
			} = client, service
			if mode == "service-half-close" {
				first, second = second, first
			}
			if _, err := io.WriteString(first, "request"); err != nil {
				t.Fatal(err)
			}
			if err := first.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			readEOF(second, "request")
			// A write EOF must not prevent a response in the other direction.
			if _, err := io.WriteString(second, "response"); err != nil {
				t.Fatal(err)
			}
			if err := second.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			readEOF(first, "response")
			if err := mc.Ping(ctx); err != nil {
				t.Fatalf("monitor after relay completed: %v", err)
			}
		})
	}
}
