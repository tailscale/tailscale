// Copyright (c) 2021 AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package peercred maps from a net.Conn to information about the
// other side of the connection, using various OS-specific facilities.
package peercred // import "inet.af/peercred"

import (
	"errors"
	"net"
	"runtime"
)

// Creds are the peer credentials.
type Creds struct {
	pid int
	uid string
}

func (c *Creds) PID() (pid int, ok bool) {
	return c.pid, c.pid != 0
}

// UserID returns the userid (or Windows SID) that owns the other side
// of the connection, if known. (ok is false if not known)
// The returned string is suitable to passing to os/user.LookupId.
func (c *Creds) UserID() (uid string, ok bool) {
	return c.uid, c.uid != ""
}

var osGet func(net.Conn) (*Creds, error)

var (
	ErrNotImplemented      = errors.New("not implemented on " + runtime.GOOS)
	ErrUnsupportedConnType = errors.New("unsupported connection type")
)

// Get returns the peer credentials for c.
//
// For unsupported system, the error is ErrNotImplemented.
func Get(c net.Conn) (*Creds, error) {
	if osGet == nil {
		return nil, ErrNotImplemented
	}
	return osGet(c)
}
