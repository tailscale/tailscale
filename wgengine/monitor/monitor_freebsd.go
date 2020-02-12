// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package monitor

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

type devdConn struct {
	conn net.Conn
}

func NewConn() (Conn, error) {
	conn, err := net.Dial("unixpacket", "/var/run/devd.seqpacket.pipe")
	if err != nil {
		return nil, fmt.Errorf("devd dial error: %v", err)
	}
	if err != nil {
		return nil, fmt.Errorf("dialing devd socket: %v", err)
	}
	return &devdConn{conn}, nil
}

func (c *devdConn) Close() error {
	return c.conn.Close()
}

func (c *devdConn) Receive() (Message, error) {
	for {
		msg, err := bufio.NewReader(c.conn).ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("reading devd socket: %v", err)
		}
		// Only return messages related to the network subsystem.
		if !strings.Contains(msg, "system=IFNET") {
			continue
		}
		// TODO(]|[): this is where the devd-specific message would
		// get converted into a "standard" event message and returned.
		return nil, nil
	}
}
