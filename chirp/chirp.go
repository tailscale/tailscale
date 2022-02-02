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
	"regexp"
	"strings"
)

// New creates a BIRDClient.
func New(socket string) (*BIRDClient, error) {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to BIRD: %w", err)
	}
	b := &BIRDClient{socket: socket, conn: conn, scanner: bufio.NewScanner(conn)}
	// Read and discard the first line as that is the welcome message.
	if _, err := b.readResponse(); err != nil {
		return nil, err
	}
	return b, nil
}

// BIRDClient handles communication with the BIRD Internet Routing Daemon.
type BIRDClient struct {
	socket  string
	conn    net.Conn
	scanner *bufio.Scanner
}

// Close closes the underlying connection to BIRD.
func (b *BIRDClient) Close() error { return b.conn.Close() }

// DisableProtocol disables the provided protocol.
func (b *BIRDClient) DisableProtocol(protocol string) error {
	out, err := b.exec("disable %s", protocol)
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
	out, err := b.exec("enable %s", protocol)
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

// BIRD CLI docs from https://bird.network.cz/?get_doc&v=20&f=prog-2.html#ss2.9

// Each session of the CLI consists of a sequence of request and replies,
// slightly resembling the FTP and SMTP protocols.
// Requests are commands encoded as a single line of text,
// replies are sequences of lines starting with a four-digit code
// followed by either a space (if it's the last line of the reply) or
// a minus sign (when the reply is going to continue with the next line),
// the rest of the line contains a textual message semantics of which depends on the numeric code.
// If a reply line has the same code as the previous one and it's a continuation line,
// the whole prefix can be replaced by a single white space character.
//
// Reply codes starting with 0 stand for ‘action successfully completed’ messages,
// 1 means ‘table entry’, 8 ‘runtime error’ and 9 ‘syntax error’.

func (b *BIRDClient) exec(cmd string, args ...interface{}) (string, error) {
	if _, err := fmt.Fprintf(b.conn, cmd, args...); err != nil {
		return "", err
	}
	fmt.Fprintln(b.conn)
	return b.readResponse()
}

var respCodeRegex = regexp.MustCompile(`^\d{4}[ -]`)

func (b *BIRDClient) readResponse() (string, error) {
	var resp strings.Builder
	var done bool
	for !done {
		if !b.scanner.Scan() {
			return "", fmt.Errorf("reading response from bird failed: %q", resp.String())
		}
		if err := b.scanner.Err(); err != nil {
			return "", err
		}
		out := b.scanner.Bytes()
		if _, err := resp.Write(out); err != nil {
			return "", err
		}
		if respCodeRegex.Match(out) {
			done = out[4] == ' '
		}
		if !done {
			resp.WriteRune('\n')
		}
	}
	return resp.String(), nil
}
