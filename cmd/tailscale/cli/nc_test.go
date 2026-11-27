// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// tcpPair returns the two ends of a loopback TCP connection.
func tcpPair(t *testing.T) (client, server *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := ln.Accept()
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.Close()
		s.Close()
	})
	return c.(*net.TCPConn), s.(*net.TCPConn)
}

func runPipeStdio(c net.Conn, stdin io.Reader, stdout io.Writer) <-chan error {
	done := make(chan error, 1)
	go func() {
		err := pipeStdio(c, stdin, stdout)
		c.Close()
		done <- err
	}()
	return done
}

func waitDone(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("pipeStdio: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pipeStdio did not return")
	}
}

// TestPipeStdioPeerHalfClose checks that stdin keeps flowing to a peer that
// has closed its write side.
func TestPipeStdioPeerHalfClose(t *testing.T) {
	client, server := tcpPair(t)

	got := make(chan string, 1)
	go func() {
		server.Write([]byte("bye\n"))
		server.CloseWrite()
		b, _ := io.ReadAll(server)
		got <- string(b)
	}()

	stdinR, stdinW := io.Pipe()
	stdout := &notifyWriter{wrote: make(chan struct{}, 1)}
	done := runPipeStdio(client, stdinR, stdout)

	// Only send once the peer's data, and so very likely its FIN, has come
	// in. Before the fix, pipeStdio returned on that FIN and closed the
	// connection.
	<-stdout.wrote
	io.WriteString(stdinW, "after peer FIN")
	stdinW.Close()

	waitDone(t, done)
	if g := <-got; g != "after peer FIN" {
		t.Errorf("peer got %q, want %q", g, "after peer FIN")
	}
	if stdout.buf.String() != "bye\n" {
		t.Errorf("stdout = %q, want %q", stdout.buf.String(), "bye\n")
	}
}

// notifyWriter is a bytes.Buffer that signals on its first write.
type notifyWriter struct {
	buf   bytes.Buffer
	wrote chan struct{}
}

func (w *notifyWriter) Write(p []byte) (int, error) {
	select {
	case w.wrote <- struct{}{}:
	default:
	}
	return w.buf.Write(p)
}

// TestPipeStdioStdinEOF checks that stdin's EOF is passed on to the peer as
// a half-close, and that the peer's reply is still copied to stdout.
func TestPipeStdioStdinEOF(t *testing.T) {
	client, server := tcpPair(t)

	go func() {
		b, _ := io.ReadAll(server) // until the client's half-close
		server.Write([]byte("got " + string(b)))
		server.Close()
	}()

	var stdout bytes.Buffer
	done := runPipeStdio(client, strings.NewReader("ping"), &stdout)
	waitDone(t, done)
	if stdout.String() != "got ping" {
		t.Errorf("stdout = %q, want %q", stdout.String(), "got ping")
	}
}

// TestPipeStdioNoHalfClose checks that, on a connection that can't be
// half-closed, pipeStdio returns once stdin reaches EOF.
func TestPipeStdioNoHalfClose(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	go io.Copy(io.Discard, server)

	done := runPipeStdio(client, strings.NewReader("ping"), io.Discard)
	waitDone(t, done)
}
