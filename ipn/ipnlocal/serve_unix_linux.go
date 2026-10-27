// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_serve

package ipnlocal

import (
	"context"
	"net"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// dialServeUnixSocketSafe dials socketPath. Where the platform allows
// it, it connects to a pinned descriptor instead of the path, so that
// swapping the path cannot retarget the connect. It returns
// ErrProxyToTailscaledSocket if the dialed socket is tailscaled's own.
// When no descriptor can be pinned, it dials the path directly.
func (b *LocalBackend) dialServeUnixSocketSafe(ctx context.Context, socketPath string) (net.Conn, error) {
	if fd, ok := pinUnixSocketPath(socketPath); ok {
		defer unix.Close(fd)

		// Check the inode held by the pin, which is the inode the
		// connect below uses.
		if b.isTailscaledSocketFd(fd) {
			b.logf("serve: refusing to proxy to the tailscaled socket %q", socketPath)
			return nil, ErrProxyToTailscaledSocket
		}
		conn, err := dialPinnedUnixSocket(ctx, fd)
		if err == nil {
			return conn, nil
		}
		// No usable /proc, or the pinned socket is gone. The peer is
		// re-checked by the caller.
		b.logf("serve: dialing %q by path: connecting through the pinned descriptor failed: %v", socketPath, err)
	}
	var d net.Dialer
	return d.DialContext(ctx, "unix", socketPath)
}

// pinUnixSocketPath returns an O_PATH descriptor referring to the file
// that socketPath resolves to, or ok=false if the kernel or the path do
// not support it (openat2(2), Linux 5.6 and newer). The resolution never
// follows magic links, and is restricted to the socket's parent directory
// when possible.
func pinUnixSocketPath(socketPath string) (fd int, ok bool) {
	if dir, base := filepath.Split(filepath.Clean(socketPath)); dir != "" && base != "." && base != ".." && base != "/" {
		if dirFD, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err == nil {
			defer unix.Close(dirFD)
			if fd, err := unix.Openat2(dirFD, base, &unix.OpenHow{
				Flags: unix.O_PATH | unix.O_CLOEXEC,
				Resolve: unix.RESOLVE_BENEATH |
					unix.RESOLVE_NO_MAGICLINKS,
			}); err == nil {
				return fd, true
			}
		}
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, socketPath, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return -1, false
	}
	return fd, true
}

// dialPinnedUnixSocket connects to the unix listener referred to by the
// O_PATH descriptor fd, via its /proc/self/fd name, so that the connect
// uses the pinned file and not the socket path.
func dialPinnedUnixSocket(ctx context.Context, fd int) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", "/proc/self/fd/"+strconv.Itoa(fd))
}

// isTailscaledSocketFd reports whether fd and the tailscaled socket
// (b.sys.SocketPath) refer to the same file, compared by device and inode.
// tailscaled's socket path is stat'ed on each call, so the directory holding
// it must not be writable by the attacker for this to be meaningful.
//
// st_dev and st_ino are filesystem-provided, and FUSE and some network
// filesystems can report zero or duplicate values. A match made that
// way still refuses the dial, so such values need no special handling.
func (b *LocalBackend) isTailscaledSocketFd(fd int) bool {
	socketPath := b.sys.SocketPath
	if socketPath == "" {
		return false
	}
	var self, pinned unix.Stat_t
	if err := unix.Stat(socketPath, &self); err != nil {
		return false
	}
	if err := unix.Fstat(fd, &pinned); err != nil {
		return false
	}
	return self.Dev == pinned.Dev && self.Ino == pinned.Ino
}
