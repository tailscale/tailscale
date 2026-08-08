// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package androidbind registers an Android-safe [netmon.InterfaceGetter] so
// that tsnet and anything else depending on interface enumeration boots
// cleanly on untrusted_app SELinux contexts (Android SDK 30+).
//
// # Why
//
// Go stdlib's [net.Interfaces] on Linux uses NETLINK_ROUTE sockets.
// Android's SELinux policy denies netlink socket creation for the default
// untrusted_app context, so any tsnet-embedded app fails at startup with
// "netlinkrib: permission denied" during interface enumeration in the
// logpolicy transport setup (see issue #17311).
//
// [netmon.RegisterInterfaceGetter] is the official hook for supplying
// an alternate enumerator — the Tailscale Android client uses it to
// route via JNI callbacks from the Java side. Embedders of tsnet in
// third-party Android apps that don't own the Java side have no way
// to fill it without writing their own JNI shim. This package is an
// opt-in, pure-Go alternative: importing it for side-effects registers
// a getter backed by libc's getifaddrs(3).
//
// # How
//
// On Android bionic (API 24+), getifaddrs is implemented on top of
// ioctl(SIOCGIFCONF) against a UDP socket — the same syscall path
// [java.net.NetworkInterface.getNetworkInterfaces] takes. Unlike
// netlink, ioctl on an AF_INET socket IS permitted for untrusted_app.
// The returned data covers the subset tsnet uses: interface names,
// up/broadcast/loopback/multicast flags, and IPv4 + IPv6 addresses
// with prefix lengths.
//
// # Usage
//
// Import the package for its side effects, before calling into tsnet:
//
//	import _ "tailscale.com/net/netmon/androidbind"
//
// No additional wiring is required. On non-Android builds the package
// compiles to a no-op.
//
// # Scope / limitations
//
// Only implemented for android/arm64 and android/amd64, the two targets
// [gomobile bind] ships for Android. Older Androids where netlink was
// still permitted fall through the stdlib-first path and keep the
// faster behaviour. If Tailscale's broader "tsnet apps should not need
// any of that stuff" direction (see #17311 comment thread) lands and
// removes interface enumeration from the tsnet startup path, this
// package becomes unnecessary in the best possible way.
//
// See tailscale/tailscale#17311.
package androidbind
