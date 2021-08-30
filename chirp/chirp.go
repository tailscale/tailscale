// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package chirp implements a client to communicate with the BIRD Internet
// Routing Daemon.
package chirp

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

// New creates a BIRDClient.
func New(socket string) (*BIRDClient, error) {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to BIRD: %w", err)
	}
	b := &BIRDClient{socket: socket, conn: conn, bs: bufio.NewScanner(conn)}
	// Read and discard the first line as that is the welcome message.
	if _, err := b.readLine(); err != nil {
		return nil, err
	}
	return b, nil
}

// BIRDClient handles communication with the BIRD Internet Routing Daemon.
type BIRDClient struct {
	socket string
	conn   net.Conn
	bs     *bufio.Scanner
}

// Close closes the underlying connection to BIRD.
func (b *BIRDClient) Close() error { return b.conn.Close() }

// DisableProtocol disables the provided protocol.
func (b *BIRDClient) DisableProtocol(protocol string) error {
	out, err := b.exec("disable %s\n", protocol)
	if err != nil {
		return err
	}
	if strings.Contains(out, fmt.Sprintf("%s: already disabled", protocol)) {
		return nil
	} else if strings.Contains(out, fmt.Sprintf("%s: disabled", protocol)) {
		return nil
	}
	return fmt.Errorf("failed to disable %s: %v", protocol, out)
}

// EnableProtocol enables the provided protocol.
func (b *BIRDClient) EnableProtocol(protocol string) error {
	out, err := b.exec("enable %s\n", protocol)
	if err != nil {
		return err
	}
	if strings.Contains(out, fmt.Sprintf("%s: already enabled", protocol)) {
		return nil
	} else if strings.Contains(out, fmt.Sprintf("%s: enabled", protocol)) {
		return nil
	}
	return fmt.Errorf("failed to enable %s: %v", protocol, out)
}

func (b *BIRDClient) exec(cmd string, args ...interface{}) (string, error) {
	if _, err := fmt.Fprintf(b.conn, cmd, args...); err != nil {
		return "", err
	}
	return b.readLine()
}

func (b *BIRDClient) readLine() (string, error) {
	if !b.bs.Scan() {
		return "", fmt.Errorf("reading response from bird failed")
	}
	if err := b.bs.Err(); err != nil {
		return "", err
	}
	return b.bs.Text(), nil
}
