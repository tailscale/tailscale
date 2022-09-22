// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package wgint provides somewhat shady access to wireguard-go
// internals that don't (yet) have public APIs.
package wgint

import (
	"reflect"
	"sync/atomic"
	"unsafe"

	"golang.zx2c4.com/wireguard/device"
)

var (
	offHandshake = getPeerStatsOffset("lastHandshakeNano")
	offRxBytes   = getPeerStatsOffset("rxBytes")
	offTxBytes   = getPeerStatsOffset("txBytes")
)

func getPeerStatsOffset(name string) uintptr {
	peerType := reflect.TypeOf(device.Peer{})
	field, ok := peerType.FieldByName(name)
	if !ok {
		panic("no " + name + " field in device.Peer")
	}
	if s := field.Type.String(); s != "atomic.Int64" && s != "atomic.Uint64" {
		panic("unexpected type " + s + " of field " + name + " in device.Peer")
	}
	return field.Offset
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
