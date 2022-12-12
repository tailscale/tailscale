// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package safesocket

import (
	"fmt"
	"net"
	"syscall"

	"github.com/Microsoft/go-winio"
)

func connect(s *ConnectionStrategy) (net.Conn, error) {
	return winio.DialPipe(s.path, nil)
}

func setFlags(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET,
			syscall.SO_REUSEADDR, 1)
	})
}

// windowsSDDL is the Security Descriptor set on the namedpipe.
// It provides read/write access to all users and the local system.
const windowsSDDL = "O:BAG:BAD:PAI(A;OICI;GWGR;;;BU)(A;OICI;GWGR;;;SY)"

func listen(path string, port uint16) (_ net.Listener, gotPort uint16, _ error) {
	lc, err := winio.ListenPipe(
		path,
		&winio.PipeConfig{
			SecurityDescriptor: windowsSDDL,
			InputBufferSize:    256 * 1024,
			OutputBufferSize:   256 * 1024,
		},
	)
	if err != nil {
		return nil, 0, fmt.Errorf("namedpipe.Listen: %w", err)
	}
	return lc, 0, nil
}
