// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

// Package androiddns resolves DNS names on Android by speaking the
// dnsproxyd protocol to the system DNS resolver daemon over its unix
// socket, the same mechanism bionic libc's getaddrinfo uses.
//
// It exists for pure Go (non-cgo) binaries built for Android, such as
// CLI tools run under Termux. Android has no /etc/resolv.conf, so
// Go's built-in resolver has no nameservers and every lookup fails.
// Binaries built with cgo don't have this problem: Go's net package
// forces the cgo resolver on Android (golang/go#10714), which calls
// bionic's getaddrinfo, which consults the same daemon this package
// talks to directly. Queries through dnsproxyd get the system's
// per-network DNS configuration and Private DNS (DNS over TLS/HTTPS)
// handling for free.
//
// # Protocol compatibility
//
// The wire protocol is unofficial but effectively frozen, for a
// structural reason rather than a policy one. Its two halves live on
// opposite sides of Android's update split. The client side (bionic's
// getaddrinfo proxy and libnetd_client) ships in the OS system image
// and updates only with a full OS update, which for most devices
// means rarely and eventually never. The server side has been the
// DnsResolver mainline (APEX) module since Android 10, updated via
// Google Play across all supported OS releases at once. A single
// current module binary must therefore keep serving the frozen libc
// clients of every supported Android version simultaneously, so
// existing commands cannot change semantics, much like a kernel
// syscall ABI with the update roles inverted. On the wire this
// package is indistinguishable from an Android 10 era bionic client,
// which cannot be broken without breaking DNS on real devices.
//
// The daemon, its socket, and the getaddrinfo-level commands date to
// 2010 (Android Gingerbread); see system/netd commit 007e987fee and
// bionic commit a1dbf0b453. The raw-packet resnsend command used here
// was added in November 2018 (system/netd commit c0c818f448) to back
// the android_res_nsend NDK API introduced in Android 10 (API 29),
// which is thus the minimum OS version this package can work on. For
// the current protocol definition, see ResNSendCommand in
// packages/modules/DnsResolver/DnsProxyListener.cpp and
// resNetworkSend in system/netd/client/NetdClient.cpp.
//
// Connecting to the socket requires membership in the AID_INET group,
// which app UIDs (including Termux) hold via the INTERNET permission,
// and SELinux policy grants app domains connect (but not stat) access
// to the socket, since every app's libc performs this exact connect.
// The plausible residual risk is not protocol change but a future
// policy tightening that distinguishes callers, so users of this
// package should treat it as best effort; the automatic installation
// into net.DefaultResolver (see auto.go) probes the socket with a
// connect first and leaves the resolver alone on failure.
//
// # Scope and gating
//
// The package also builds on GOOS=linux, not just GOOS=android,
// because static linux binaries run fine under Android kernels
// (Termux users and rooted devices commonly run our official static
// linux/arm64 builds) and have the same broken resolver there. Those
// builds detect Android at runtime before installing anything: no
// /etc/resolv.conf, the presence of /dev/__properties__ (the bionic
// property service's backing store, present since Android 5.0 and
// never on regular Linux), and a successful dnsproxyd connect.
//
// This is an optional feature, included by default in tailscaled
// builds on Linux and Android; build with the ts_omit_androiddns tag
// to omit it. It is not linked into tsnet by default; tsnet apps and
// other programs opt in with a blank import of this package.
package androiddns

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"
)

// socketPath is the dnsproxyd unix socket path. It's a variable only
// so tests can point it at a fake server.
var socketPath = "/dev/socket/dnsproxyd"

// maxCmdSize is FrameworkListener's CMD_BUF_SIZE in AOSP: the entire
// command, including the trailing NUL, must arrive in a single read
// of at most this many bytes.
const maxCmdSize = 1024

// maxAnswerSize is the maximum answer length we accept from the
// daemon. The daemon's own limit (MAXPACKET) is 8 KiB; we allow more
// in case it ever grows.
const maxAnswerSize = 64 << 10

// Query sends the wire-format DNS query msg to the system resolver
// daemon and returns the wire-format answer. The answer's ID matches
// the query's ID. An unsuccessful rcode (such as NXDOMAIN) is not an
// error; it's returned in the answer's header for the caller to
// interpret.
//
// The query is resolved on the default network with the system's
// usual policy for the calling UID, as if the process had called
// bionic's getaddrinfo.
func Query(ctx context.Context, msg []byte) ([]byte, error) {
	// The command is "resnsend <netId> <flags> <base64 query>\x00".
	// netId 0 is NETID_UNSET, meaning the caller's default network.
	cmd := "resnsend 0 0 " + base64.StdEncoding.EncodeToString(msg) + "\x00"
	if len(cmd) > maxCmdSize {
		return nil, fmt.Errorf("androiddns: %d byte query too large for dnsproxyd command buffer", len(msg))
	}

	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("androiddns: %w", err)
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		c.SetDeadline(deadline)
	}

	// FrameworkListener does a single read and requires the NUL to be
	// in it, so the command must go out in one write.
	if _, err := c.Write([]byte(cmd)); err != nil {
		return nil, fmt.Errorf("androiddns: %w", err)
	}
	if uc, ok := c.(*net.UnixConn); ok {
		uc.CloseWrite()
	}

	// The reply is a big-endian int32 that's either a negative errno
	// or the rcode, followed on success by a big-endian int32 answer
	// length and the raw answer.
	var buf [4]byte
	if _, err := io.ReadFull(c, buf[:]); err != nil {
		return nil, fmt.Errorf("androiddns: reading result: %w", err)
	}
	if res := int32(binary.BigEndian.Uint32(buf[:])); res < 0 {
		return nil, fmt.Errorf("androiddns: dnsproxyd error %d (%v)", res, syscall.Errno(-res))
	}
	if _, err := io.ReadFull(c, buf[:]); err != nil {
		return nil, fmt.Errorf("androiddns: reading answer length: %w", err)
	}
	ansLen := int32(binary.BigEndian.Uint32(buf[:]))
	if ansLen < 0 || ansLen > maxAnswerSize {
		return nil, fmt.Errorf("androiddns: bogus answer length %d", ansLen)
	}
	ans := make([]byte, ansLen)
	if _, err := io.ReadFull(c, ans); err != nil {
		return nil, fmt.Errorf("androiddns: reading answer: %w", err)
	}
	return ans, nil
}

// available reports whether the dnsproxyd socket exists and accepts
// connections. It's a connect test rather than a stat because SELinux
// grants app domains connect access to the socket without getattr.
func available() bool {
	c, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}
