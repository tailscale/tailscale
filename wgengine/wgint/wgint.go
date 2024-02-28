// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package wgint provides somewhat shady access to wireguard-go
// internals that don't (yet) have public APIs.
package wgint

import (
	"reflect"
	"sync/atomic"
	"time"
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

// peerLastHandshakeNano returns the last handshake time in nanoseconds since the
// unix epoch.
func peerLastHandshakeNano(peer *device.Peer) int64 {
	return (*atomic.Int64)(unsafe.Add(unsafe.Pointer(peer), offHandshake)).Load()
}

// peerRxBytes returns the number of bytes received from this peer.
func peerRxBytes(peer *device.Peer) uint64 {
	return (*atomic.Uint64)(unsafe.Add(unsafe.Pointer(peer), offRxBytes)).Load()
}

// peerTxBytes returns the number of bytes sent to this peer.
func peerTxBytes(peer *device.Peer) uint64 {
	return (*atomic.Uint64)(unsafe.Add(unsafe.Pointer(peer), offTxBytes)).Load()
}

// peerHandshakeAttempts returns the number of WireGuard handshake attempts
// made for the current handshake. It resets to zero before every new handshake.
func peerHandshakeAttempts(peer *device.Peer) uint32 {
	return (*atomic.Uint32)(unsafe.Add(unsafe.Pointer(peer), offHandshakeAttempts)).Load()
}

// Peer is a wrapper around a wireguard-go device.Peer pointer.
type Peer struct {
	p *device.Peer
}

// PeerOf returns a Peer wrapper around a wireguard-go device.Peer.
func PeerOf(p *device.Peer) Peer {
	return Peer{p}
}

// LastHandshake returns the last handshake time.
//
// If the handshake has never happened, it returns the zero value.
func (p Peer) LastHandshake() time.Time {
	if n := peerLastHandshakeNano(p.p); n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

func (p Peer) IsValid() bool { return p.p != nil }

// TxBytes returns the number of bytes sent to this peer.
func (p Peer) TxBytes() uint64 { return peerTxBytes(p.p) }

// RxBytes returns the number of bytes received from this peer.
func (p Peer) RxBytes() uint64 { return peerRxBytes(p.p) }

// HandshakeAttempts returns the number of failed WireGuard handshake attempts
// made for the current handshake. It resets to zero before every new handshake
// and after a successful handshake.
func (p Peer) HandshakeAttempts() uint32 {
	return peerHandshakeAttempts(p.p)
}
