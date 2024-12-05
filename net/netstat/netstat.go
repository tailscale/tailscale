// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package netstat returns the local machine's network connection table.
package netstat

import (
	"errors"
	"net/netip"
	"runtime"
)

var ErrNotImplemented = errors.New("not implemented for GOOS=" + runtime.GOOS)

type Entry struct {
	Local, Remote netip.AddrPort
	Pid           int
	State         string // TODO: type?
	OSMetadata    OSMetadata
}

// Table contains local machine's TCP connection entries.
//
// Currently only TCP (IPv4 and IPv6) are included.
type Table struct {
	Entries []Entry
}

// Get returns the connection table.
//
// It returns ErrNotImplemented if the table is not available for the
// current operating system.
func Get() (*Table, error) {
	return get()
}
