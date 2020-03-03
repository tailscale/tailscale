// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !windows

package safesocket

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// TODO(apenwarr): handle magic cookie auth
func connect(path string, port uint16) (net.Conn, error) {
	pipe, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	return pipe, err
}

// TODO(apenwarr): handle magic cookie auth
func listen(path string, port uint16) (ln net.Listener, _ uint16, err error) {
	// Unix sockets hang around in the filesystem even after nobody
	// is listening on them. (Which is really unfortunate but long-
	// entrenched semantics.) Try connecting first; if it works, then
	// the socket is still live, so let's not replace it. If it doesn't
	// work, then replace it.
	//
	// Note that there's a race condition between these two steps. A
	// "proper" daemon usually uses a dance involving pidfiles to first
	// ensure that no other instances of itself are running, but that's
	// beyond the scope of our simple socket library.
	c, err := net.Dial("unix", path)
	if err == nil {
		c.Close()
		return nil, 0, fmt.Errorf("%v: address already in use", path)
	}
	_ = os.Remove(path)
	os.MkdirAll(filepath.Dir(path), 0755) // best effort
	pipe, err := net.Listen("unix", path)
	if err != nil {
		return nil, 0, err
	}
	os.Chmod(path, 0666)
	return pipe, 0, err
}
