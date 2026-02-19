// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package rioconn

import (
	"cmp"
	"errors"
	"math"
	"syscall"
)

const (
	// TODO(nickkhyl): Determine defaults automatically based on NIC and link properties.

	defaultRXMemoryLimit = 2 << 20 // 2 MiB
	defaultTXMemoryLimit = 2 << 20 // 2 MiB
)

// Config holds configuration for a RIO connection, independent of the transport protocol.
type Config struct {
	control []func(network, address string, c syscall.RawConn) error
	rx      RxConfig
	tx      TxConfig
}

// Control invokes all control functions in the Config with the given
// network, address, and connection. A failure of one control function
// does not prevent the others from running. It returns an error if any
// control function fails.
func (c Config) Control(network string, address string, conn syscall.RawConn) error {
	var err []error
	for _, control := range c.control {
		if e := control(network, address, conn); e != nil {
			err = append(err, e)
		}
	}
	return errors.Join(err...)
}

// Rx returns the receive path configuration.
func (c Config) Rx() *RxConfig {
	return &c.rx
}

// Tx returns the transmit path configuration.
func (c Config) Tx() *TxConfig {
	return &c.tx
}

// RxConfig holds configuration for the receive path of a RIO connection.
type RxConfig struct {
	memoryLimit   uintptr // 0 means default
	maxPayloadLen uint16  // 0 means default
}

// MemoryLimit returns the maximum memory allowed for the receive path.
func (o RxConfig) MemoryLimit() uintptr {
	return cmp.Or(o.memoryLimit, defaultRXMemoryLimit)
}

// MaxPayloadLen returns the maximum number of bytes allowed in a
// single packet. Packets larger than this limit may be dropped.
// It returns [math.MaxUint16] if no limit is applied other than the
// maximum packet size supported by the connection's transport protocol.
func (o RxConfig) MaxPayloadLen() uint16 {
	return cmp.Or(o.maxPayloadLen, math.MaxUint16)
}

// TxConfig holds configuration for the transmit path of a RIO connection.
type TxConfig struct {
	memoryLimit   uintptr // 0 means default
	maxPayloadLen uint16  // 0 means default
}

// MemoryLimit returns the maximum memory allowed for the transmit path.
func (o TxConfig) MemoryLimit() uintptr {
	return cmp.Or(o.memoryLimit, defaultTXMemoryLimit)
}

// MaxPayloadLen returns the maximum number of bytes that may be sent
// in a single packet. Sending packets larger than this limit may fail.
// It returns [math.MaxUint16] if no limit is applied other than the
// maximum packet size supported by the connection's transport protocol.
func (o TxConfig) MaxPayloadLen() uint16 {
	return cmp.Or(o.maxPayloadLen, math.MaxUint16)
}

// UDPConfig holds configuration for a [UDPConn].
type UDPConfig struct {
	Config
}
