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
	sf, ok := peerType.FieldByName("stats")
	if !ok {
		panic("no stats field in device.Peer")
	}
	if sf.Type.Kind() != reflect.Struct {
		panic("stats field is not a struct")
	}
	base := sf.Offset

	st := sf.Type
	field, ok := st.FieldByName(name)
	if !ok {
		panic("no " + name + " field in device.Peer.stats")
	}
	if field.Type.Kind() != reflect.Int64 && field.Type.Kind() != reflect.Uint64 {
		panic("unexpected kind of " + name + " field in device.Peer.stats")
	}
	return base + field.Offset
}

// PeerLastHandshakeNano returns the last handshake time in nanoseconds since the
// unix epoch.
func PeerLastHandshakeNano(peer *device.Peer) int64 {
	return atomic.LoadInt64((*int64)(unsafe.Add(unsafe.Pointer(peer), offHandshake)))
}

// PeerRxBytes returns the number of bytes received from this peer.
func PeerRxBytes(peer *device.Peer) uint64 {
	return atomic.LoadUint64((*uint64)(unsafe.Add(unsafe.Pointer(peer), offRxBytes)))
}

// PeerTxBytes returns the number of bytes sent to this peer.
func PeerTxBytes(peer *device.Peer) uint64 {
	return atomic.LoadUint64((*uint64)(unsafe.Add(unsafe.Pointer(peer), offTxBytes)))
}
