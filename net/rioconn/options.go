// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package rioconn

import (
	"syscall"
)

// Option is any option that can be applied to a RIO connection,
// independent of the transport protocol.
type Option interface {
	UDPOption
}

// UDPOption is any option that can be applied to a [UDPConn].
type UDPOption interface {
	applyUDP(*UDPConfig)
}

type option func(*Config)

func (o option) applyUDP(opts *UDPConfig) {
	o(&opts.Config)
}

// Control specifies an optional function that will be called after creating
// the network connection but before binding it to the operating system.
func Control(control func(network, address string, c syscall.RawConn) error) Option {
	return option(func(opts *Config) {
		if control != nil {
			opts.control = append(opts.control, control)
		}
	})
}

// RxMemoryLimit specifies the maximum memory to use for the receive path.
func RxMemoryLimit(bytes uintptr) Option {
	return option(func(opts *Config) {
		opts.rx.memoryLimit = bytes
	})
}

// RxMaxPayloadLen specifies the maximum payload size, in bytes, accepted
// for a single received packet. Packets exceeding this limit may be dropped.
// If unset or set to zero, no limit is applied other than the maximum packet
// size supported by the connection's transport protocol.
func RxMaxPayloadLen(bytes uintptr) Option {
	return option(func(opts *Config) {
		opts.rx.maxPayloadLen = uint16(bytes)
	})
}

// TxMemoryLimit specifies the maximum memory to use for the transmit path.
func TxMemoryLimit(bytes uintptr) Option {
	return option(func(opts *Config) {
		opts.tx.memoryLimit = bytes
	})
}

// TxMaxPayloadLen specifies the maximum payload size, in bytes, accepted
// for transmission in a single packet. Attempting to send packets exceeding
// this limit may fail. If unset or set to zero, no limit is applied other than
// the maximum packet size supported by the connection's transport protocol
// and underlying link or hardware capabilities.
func TxMaxPayloadLen(bytes uintptr) Option {
	return option(func(opts *Config) {
		opts.tx.maxPayloadLen = uint16(bytes)
	})
}

type udpOption func(*UDPConfig)

func (o udpOption) applyUDP(opts *UDPConfig) {
	o(opts)
}

// USO specifies whether UDP segmentation offload (USO) should be enabled.
func USO(enabled bool) UDPOption {
	return udpOption(func(opts *UDPConfig) {
		opts.uso.enabled = enabled
	})
}
