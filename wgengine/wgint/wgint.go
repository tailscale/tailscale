// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package wgint provides somewhat shady access to wireguard-go
// internals that don't (yet) have public APIs.
package wgint

import (
	"reflect"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
)

var (
	offHandshake = getPeerStatsOffset("lastHandshakeNano")
	offRxBytes   = getPeerStatsOffset("rxBytes")
	offTxBytes   = getPeerStatsOffset("txBytes")

	offHandshakeAttempts = getPeerHandshakeAttemptsOffset()

	offEndpoint, offEndpointVal = getPeerEndpointOffsets()
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

// getPeerEndpointOffsets returns the offset of the unexported
// device.Peer.endpoint struct within device.Peer, and the offset of its "val"
// field (the peer's current [conn.Endpoint]) within that struct. It verifies
// that the struct's first field is its guarding [sync.Mutex] at offset zero.
func getPeerEndpointOffsets() (epOff, valOff uintptr) {
	peerType := reflect.TypeFor[device.Peer]()
	field, ok := peerType.FieldByName("endpoint")
	if !ok {
		panic("no endpoint field in device.Peer")
	}
	if field.Type.Kind() != reflect.Struct || field.Type.NumField() == 0 {
		panic("unexpected type " + field.Type.String() + " of field endpoint in device.Peer")
	}
	if mf := field.Type.Field(0); mf.Type != reflect.TypeFor[sync.Mutex]() || mf.Offset != 0 {
		panic("first field of device.Peer.endpoint is not a sync.Mutex at offset 0")
	}
	valField, ok := field.Type.FieldByName("val")
	if !ok {
		panic("no val field in device.Peer.endpoint")
	}
	if g, w := valField.Type, reflect.TypeFor[conn.Endpoint](); g != w {
		panic("unexpected type " + g.String() + " of field val in device.Peer.endpoint; want " + w.String())
	}
	return field.Offset, valField.Offset
}

// peerEndpoint returns the peer's current endpoint, holding its lock for the
// read as wireguard-go's own accesses do.
func peerEndpoint(peer *device.Peer) conn.Endpoint {
	ep := unsafe.Add(unsafe.Pointer(peer), offEndpoint)
	mu := (*sync.Mutex)(ep) // guards the endpoint struct; verified to be its first field
	mu.Lock()
	defer mu.Unlock()
	return *(*conn.Endpoint)(unsafe.Add(ep, offEndpointVal))
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

// Endpoint returns the peer's current endpoint: the [conn.Endpoint] that
// wireguard-go uses to transmit to the peer. It is nil if wireguard-go holds
// no endpoint for the peer.
func (p Peer) Endpoint() conn.Endpoint {
	return peerEndpoint(p.p)
}
