// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_serve

package ipnlocal

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// openat2Supported reports whether the kernel supports openat2(2)
// (Linux 5.6 and newer).
func openat2Supported() bool {
	fd, err := unix.Openat2(unix.AT_FDCWD, "/", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC})
	if err == nil {
		unix.Close(fd)
		return true
	}
	return false
}

// TestPinUnixSocketPathResistsSymlinkSwap checks that replacing the dial
// path with a symlink after pinning does not change the pinned descriptor,
// and that a later pin of the swapped path refers to the tailscaled socket.
func TestPinUnixSocketPathResistsSymlinkSwap(t *testing.T) {
	if !openat2Supported() {
		t.Skip("kernel does not support openat2(2); the dial falls back to the pre/post checks")
	}

	dir := unixSocketTestDir(t)
	tsSock := filepath.Join(dir, "tailscaled.sock")
	mustListenUnix(t, tsSock)
	backend := filepath.Join(dir, "backend.sock")
	serveUnixEchoListener(t, backend)

	b := newTestBackend(t)
	b.sys.SocketPath = tsSock

	// Backend behind a sibling symlink.
	alias := filepath.Join(dir, "alias.sock")
	if err := os.Symlink("backend.sock", alias); err != nil {
		t.Fatal(err)
	}

	fd, ok := pinUnixSocketPath(alias)
	if !ok {
		t.Fatalf("pinUnixSocketPath(%q) did not pin", alias)
	}
	defer unix.Close(fd)

	if b.isTailscaledSocketFd(fd) {
		t.Fatal("pin of the benign alias matches the tailscaled socket")
	}

	// Replace the path with a symlink to the tailscaled socket after the pin.
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("tailscaled.sock", alias); err != nil {
		t.Fatal(err)
	}

	// The pinned descriptor is unchanged...
	if b.isTailscaledSocketFd(fd) {
		t.Fatal("pin followed the swap onto the tailscaled socket")
	}
	// ...and the connect through it reaches the benign backend, not the
	// socket the path now leads to.
	c, err := dialPinnedUnixSocket(context.Background(), fd)
	if err != nil {
		t.Fatalf("dial through the pinned descriptor: %v", err)
	}
	defer c.Close()
	msg := []byte("hello backend")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo through pin = %q; want %q", got, msg)
	}

	// A new pin of the swapped path is the tailscaled socket.
	fd, ok = pinUnixSocketPath(alias)
	if !ok {
		t.Fatalf("pinUnixSocketPath(%q) on the swapped path did not pin", alias)
	}
	defer unix.Close(fd)
	if !b.isTailscaledSocketFd(fd) {
		t.Fatal("pin of the swapped alias is not the tailscaled socket")
	}
}

// TestPinUnixSocketPathAbsoluteSymlinkBackend checks that a backend behind
// an absolute symlink, which RESOLVE_BENEATH cannot resolve, is still
// pinned and dialable.
func TestPinUnixSocketPathAbsoluteSymlinkBackend(t *testing.T) {
	if !openat2Supported() {
		t.Skip("kernel does not support openat2(2); the dial falls back to the pre/post checks")
	}

	dir := unixSocketTestDir(t)
	backend := filepath.Join(dir, "backend.sock")
	serveUnixEchoListener(t, backend)

	alias := filepath.Join(dir, "alias.sock")
	if err := os.Symlink(backend, alias); err != nil {
		t.Fatal(err)
	}

	fd, ok := pinUnixSocketPath(alias)
	if !ok {
		t.Fatalf("pinUnixSocketPath(%q) did not pin", alias)
	}
	defer unix.Close(fd)

	c, err := dialPinnedUnixSocket(context.Background(), fd)
	if err != nil {
		t.Fatalf("dial through the pinned descriptor: %v", err)
	}
	defer c.Close()
	msg := []byte("hello backend")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo through pin = %q; want %q", got, msg)
	}
}

// TestPinUnixSocketPathRefusesMagicLinks checks that a path that is a magic
// link (here, /proc/self/fd of the listener) is not pinned.
func TestPinUnixSocketPathRefusesMagicLinks(t *testing.T) {
	if !openat2Supported() {
		t.Skip("kernel does not support openat2(2); the dial falls back to the pre/post checks")
	}

	dir := unixSocketTestDir(t)
	tsSock := filepath.Join(dir, "tailscaled.sock")
	ln := mustListenUnix(t, tsSock)

	sc, ok := ln.(syscall.Conn)
	if !ok {
		t.Fatalf("%T does not expose its descriptor", ln)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var lnFD int
	if err := rc.Control(func(fd uintptr) { lnFD = int(fd) }); err != nil {
		t.Fatal(err)
	}

	magic := filepath.Join(dir, "magic.sock")
	if err := os.Symlink("/proc/self/fd/"+strconv.Itoa(lnFD), magic); err != nil {
		t.Fatal(err)
	}

	if fd, ok := pinUnixSocketPath(magic); ok {
		unix.Close(fd)
		t.Fatal("pinUnixSocketPath pinned through a magic link; want it refused")
	}
}
