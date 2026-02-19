// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package rioconn

import (
	"errors"
	"syscall"
)

// Config holds configuration for a RIO connection, independent of the transport protocol.
type Config struct {
	control []func(network, address string, c syscall.RawConn) error
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
