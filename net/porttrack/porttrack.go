// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package porttrack provides race-free ephemeral port assignment for
// subprocess tests. The parent test process creates a [Collector] that
// listens on a TCP port; the child process uses [Listen] which, when
// given a magic address, binds to localhost:0 and reports the actual
// port back to the collector.
//
// The magic address format is:
//
//	testport-report-LABEL:PORT
//
// where localhost:PORT is the collector's TCP address and LABEL identifies
// which listener this is (e.g. "main", "plaintext").
//
// When [Listen] is called with a non-magic address, it falls through to
// [net.Listen] with zero overhead beyond a single [strings.HasPrefix]
// check.
package porttrack

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"tailscale.com/util/testenv"
)

const magicPrefix = "testport-report-"

// Collector is the parent/test side of the porttrack protocol. It
// listens for port reports from child processes that used [Listen]
// with a magic address obtained from [Collector.Addr].
type Collector struct {
	ln     net.Listener
	lnPort int
	mu     sync.Mutex
	cond   *sync.Cond
	ports  map[string]int
	err    error // non-nil if a context passed to Port was cancelled
}

// NewCollector creates a new Collector. The collector's TCP listener is
// closed when t finishes.
func NewCollector(t testenv.TB) *Collector {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("porttrack.NewCollector: %v", err)
	}
	c := &Collector{
		ln:     ln,
		lnPort: ln.Addr().(*net.TCPAddr).Port,
		ports:  make(map[string]int),
	}
	c.cond = sync.NewCond(&c.mu)
	go c.accept(t)
	t.Cleanup(func() { ln.Close() })
	return c
}

// accept runs in a goroutine, accepting connections and parsing port
// reports until the listener is closed.
func (c *Collector) accept(t testenv.TB) {
	for {
		conn, err := c.ln.Accept()
		if err != nil {
			return // listener closed
		}
		go c.handleConn(t, conn)
	}
}

func (c *Collector) handleConn(t testenv.TB, conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		label, portStr, ok := strings.Cut(line, "\t")
		if !ok {
			t.Errorf("porttrack: malformed report line: %q", line)
			return
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			t.Errorf("porttrack: bad port in report %q: %v", line, err)
			return
		}
		c.mu.Lock()
		c.ports[label] = port
		c.cond.Broadcast()
		c.mu.Unlock()
	}
}

// Addr returns a magic address string that, when passed to [Listen],
// causes the child to bind to localhost:0 and report its actual port
// back to this collector under the given label.
func (c *Collector) Addr(label string) string {
	for _, c := range label {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-':
		default:
			panic(fmt.Sprintf("invalid label %q: only letters, digits, and hyphens are allowed", label))
		}
	}
	return fmt.Sprintf("%s%s:%d", magicPrefix, label, c.lnPort)
}

// Port blocks until the child process has reported the port for the
// given label, then returns it. If ctx is cancelled before a port is
// reported, Port returns the context's cause as an error.
func (c *Collector) Port(ctx context.Context, label string) (int, error) {
	stop := context.AfterFunc(ctx, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.err == nil {
			c.err = context.Cause(ctx)
		}
		c.cond.Broadcast()
	})
	defer stop()

	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if p, ok := c.ports[label]; ok {
			return p, nil
		}
		if c.err != nil {
			return 0, c.err
		}
		c.cond.Wait()
	}
}

// Listen is the child/production side of the porttrack protocol.
//
// If address has the magic prefix (as returned by [Collector.Addr]),
// Listen binds to localhost:0 on the given network, then TCP-connects
// to the collector and writes "LABEL\tPORT\n" to report the actual
// port. The collector connection is closed before returning.
//
// If address does not have the magic prefix, Listen is simply
// [net.Listen](network, address).
func Listen(network, address string) (net.Listener, error) {
	rest, ok := strings.CutPrefix(address, magicPrefix)
	if !ok {
		return net.Listen(network, address)
	}

	// rest is LABEL:PORT.
	label, collectorPort, ok := strings.Cut(rest, ":")
	if !ok {
		return nil, fmt.Errorf("porttrack: malformed magic address %q: missing :PORT", address)
	}

	ln, err := net.Listen(network, "localhost:0")
	if err != nil {
		return nil, err
	}

	port := ln.Addr().(*net.TCPAddr).Port

	collectorAddr := net.JoinHostPort("localhost", collectorPort)
	conn, err := net.Dial("tcp", collectorAddr)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("porttrack: failed to connect to collector at %s: %v", collectorAddr, err)
	}
	_, err = fmt.Fprintf(conn, "%s\t%d\n", label, port)
	conn.Close()
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("porttrack: failed to report port to collector: %v", err)
	}

	return ln, nil
}
