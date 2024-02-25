// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package wgint provides somewhat shady access to wireguard-go
// internals that don't (yet) have public APIs.
package wgint

import (
	"reflect"
	"sync/atomic"
	"unsafe"

	"github.com/tailscale/wireguard-go/device"
)

var (
	offHandshake = getPeerStatsOffset("lastHandshakeNano")
	offRxBytes   = getPeerStatsOffset("rxBytes")
	offTxBytes   = getPeerStatsOffset("txBytes")

	offHandshakeAttempts = getPeerHandshakeAttemptsOffset()
)

func getPeerStatsOffset(name string) uintptr {
	peerType := reflect.TypeFor[device.Peer]()
	field, ok := peerType.FieldByName(name)
	if !ok {
		panic("no " + name + " field in device.Peer")
	}
	if s := field.Type.String(); s != "atomic.Int64" && s != "atomic.Uint64" {
		panic("unexpected type " + s + " of field " + name + " in device.Peer")
	}
	return field.Offset
}

func getPeerHandshakeAttemptsOffset() uintptr {
	peerType := reflect.TypeFor[device.Peer]()
	field, ok := peerType.FieldByName("timers")
	if !ok {
		panic("no timers field in device.Peer")
	}
	field2, ok := field.Type.FieldByName("handshakeAttempts")
	if !ok {
		panic("no handshakeAttempts field in device.Peer.timers")
	}
	if g, w := field2.Type.String(), "atomic.Uint32"; g != w {
		panic("unexpected type " + g + " of field handshakeAttempts in device.Peer.timers; want " + w)
	}
	return field.Offset + field2.Offset
}

// PeerLastHandshakeNano returns the last handshake time in nanoseconds since the
// unix epoch.
func PeerLastHandshakeNano(peer *device.Peer) int64 {
	return (*atomic.Int64)(unsafe.Add(unsafe.Pointer(peer), offHandshake)).Load()
}

// PeerRxBytes returns the number of bytes received from this peer.
func PeerRxBytes(peer *device.Peer) uint64 {
	return (*atomic.Uint64)(unsafe.Add(unsafe.Pointer(peer), offRxBytes)).Load()
}

// PeerTxBytes returns the number of bytes sent to this peer.
func PeerTxBytes(peer *device.Peer) uint64 {
	return (*atomic.Uint64)(unsafe.Add(unsafe.Pointer(peer), offTxBytes)).Load()
}

// PeerHandshakeAttempts returns the number of WireGuard handshake attempts
// made for the current handshake. It resets to zero before every new handshake.
func PeerHandshakeAttempts(peer *device.Peer) uint32 {
	return (*atomic.Uint32)(unsafe.Add(unsafe.Pointer(peer), offHandshakeAttempts)).Load()
}
