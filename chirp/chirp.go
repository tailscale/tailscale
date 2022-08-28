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
	"time"
)

const (
	// Maximum amount of time we should wait when reading a response from BIRD.
	responseTimeout = 10 * time.Second
)

// New creates a BIRDClient.
func New(socket string) (*BIRDClient, error) {
	return newWithTimeout(socket, responseTimeout)
}

func newWithTimeout(socket string, timeout time.Duration) (*BIRDClient, error) {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to BIRD: %w", err)
	}
	b := &BIRDClient{
		socket:  socket,
		conn:    conn,
		scanner: bufio.NewScanner(conn),
		timeNow: time.Now,
		timeout: timeout,
	}
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
	timeNow func() time.Time
	timeout time.Duration
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

func (b *BIRDClient) exec(cmd string, args ...any) (string, error) {
	if err := b.conn.SetWriteDeadline(b.timeNow().Add(b.timeout)); err != nil {
		return "", err
	}
	if _, err := fmt.Fprintf(b.conn, cmd, args...); err != nil {
		return "", err
	}
	if _, err := fmt.Fprintln(b.conn); err != nil {
		return "", err
	}
	return b.readResponse()
}

// hasResponseCode reports whether the provided byte slice is
// prefixed with a BIRD response code.
// Equivalent regex: `^\d{4}[ -]`.
func hasResponseCode(s []byte) bool {
	if len(s) < 5 {
		return false
	}
	for _, b := range s[:4] {
		if '0' <= b && b <= '9' {
			continue
		}
		return false
	}
	return s[4] == ' ' || s[4] == '-'
}

func (b *BIRDClient) readResponse() (string, error) {
	// Set the read timeout before we start reading anything.
	if err := b.conn.SetReadDeadline(b.timeNow().Add(b.timeout)); err != nil {
		return "", err
	}

	var resp strings.Builder
	var done bool
	for !done {
		if !b.scanner.Scan() {
			if err := b.scanner.Err(); err != nil {
				return "", err
			}

			return "", fmt.Errorf("reading response from bird failed (EOF): %q", resp.String())
		}
		out := b.scanner.Bytes()
		if _, err := resp.Write(out); err != nil {
			return "", err
		}
		if hasResponseCode(out) {
			done = out[4] == ' '
		}
		if !done {
			resp.WriteRune('\n')
		}
	}
	return resp.String(), nil
}
