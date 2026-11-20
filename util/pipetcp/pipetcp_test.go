// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package pipetcp

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"tailscale.com/types/nettype"
	"tailscale.com/util/must"
)

// halfCloseCheckingTCPConn is a TCPConn that keeps track of if its write end
// was closed.
type halfCloseCheckingTCPConn struct {
	net.Conn
	halfClosed bool
}

func (c *halfCloseCheckingTCPConn) CloseWrite() error {
	c.halfClosed = true
	return c.Conn.(nettype.TCPWriteCloser).CloseWrite()
}

// brokenReadConn is a Conn that returns an error on Read.
type brokenReadConn struct {
	net.Conn
}

func (c *brokenReadConn) Read(_ []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func (c *brokenReadConn) WriteTo(_ io.Writer) (int64, error) {
	return 0, io.ErrClosedPipe
}

// brokenWriteConn is a Conn that returns an error on Write.
type brokenWriteConn struct {
	net.Conn
}

func (c *brokenWriteConn) Write(_ []byte) (int, error) {
	// CloseWrite so that the backing connection knows we won't write anything.
	c.CloseWrite()
	return 0, io.ErrClosedPipe
}

func (c *brokenWriteConn) ReadFrom(_ io.Reader) (int64, error) {
	// CloseWrite so that the backing connection knows we won't write anything.
	c.CloseWrite()
	return 0, io.ErrClosedPipe
}

func (c *brokenWriteConn) CloseWrite() error {
	return c.Conn.(nettype.TCPWriteCloser).CloseWrite()
}

// peerSimulator is a function that runs in its own goroutine to pretend to be
// a computer on the other side of a connection. It sends exactly one value over
// errc (either an error if one occurred, or nil otherwise), and plays its part
// in a conversation between a client that sends `request`, and closes its
// write end, and a backend that responds with `response`.
type peerSimulator func(conn net.Conn, errc chan<- error, request, response []byte)

// connModifier wraps a [*net.TCPConn] in modifiers to mock functionality.
type connModifier func(*net.TCPConn) net.Conn

func goodClient(client net.Conn, errc chan<- error, request, response []byte) {
	defer func() { client.Close() }()
	if _, err := client.Write(request); err != nil {
		errc <- fmt.Errorf("client write: %v", err)
		return
	}
	if err := client.(nettype.TCPWriteCloser).CloseWrite(); err != nil {
		errc <- fmt.Errorf("client closewrite: %v", err)
		return
	}
	got, err := io.ReadAll(client)
	if err != nil {
		errc <- fmt.Errorf("client read: %v", err)
		return
	}
	if !bytes.Equal(got, response) {
		errc <- fmt.Errorf("client read: expected response length %v, got %v", len(response), len(got))
		return
	}
	errc <- nil
}

func goodBackend(backend net.Conn, errc chan<- error, request, response []byte) {
	defer func() { backend.Close() }()
	got, err := io.ReadAll(backend)
	if err != nil {
		errc <- fmt.Errorf("backend read: %v", err)
		return
	}
	if !bytes.Equal(got, request) {
		errc <- fmt.Errorf("backend read: expected request length %v, got %v", len(request), len(got))
		return
	}
	if _, err = backend.Write(response); err != nil {
		errc <- fmt.Errorf("backend write: %v", err)
		return
	}
	errc <- nil
}

func TestPipe(t *testing.T) {
	tests := []struct {
		name              string
		client            peerSimulator
		backend           peerSimulator
		toClientModifier  connModifier
		toBackendModifier connModifier
		wantPipeError     bool
		wantHalfClosed    bool
		wantClientError   bool
		wantBackendError  bool
	}{
		{
			name:             "success",
			client:           goodClient,
			backend:          goodBackend,
			wantPipeError:    false,
			wantClientError:  false,
			wantBackendError: false,
			wantHalfClosed:   true,
		},
		{
			name:    "error-writing-to-backend",
			client:  goodClient,
			backend: goodBackend,
			toBackendModifier: func(c *net.TCPConn) net.Conn {
				return &brokenWriteConn{c}
			},
			wantPipeError:    true,
			wantClientError:  true,
			wantBackendError: true,
			wantHalfClosed:   false,
		},
		{
			name: "error-reading-from-client",
			client: func(conn net.Conn, errc chan<- error, request, response []byte) {
				// We will never successfully read from this client, so might
				// as well close it immediately.
				errc <- conn.Close()
			},
			backend: goodBackend,
			toClientModifier: func(c *net.TCPConn) net.Conn {
				return &brokenReadConn{c}
			},
			wantPipeError:    true,
			wantClientError:  false, // the client we wrote above never has a chance to error
			wantBackendError: true,
			wantHalfClosed:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// makePeer makes a "peer", ie. an approximation of a computer that we are
			// talking to over a TCP connection.
			// peer is the end that we use to pretend to be the other computer.
			// proxy is the end that we use to talk to the other computer.
			makePeer := func() (peer, proxy net.Conn, cleanup func()) {
				t.Helper()
				ln := must.Get(net.Listen("tcp", "127.0.0.1:0"))
				peerCh := make(chan net.Conn, 1)
				go func() {
					peerCh <- must.Get(ln.Accept())
				}()
				proxy = must.Get(net.Dial("tcp", ln.Addr().String()))
				peer = <-peerCh
				return peer, proxy, func() {
					ln.Close()
					peer.Close()
					proxy.Close()
				}
			}

			// Create a "backend" server to forward connections to.
			backend, toBackend, cleanupBackend := makePeer()
			defer cleanupBackend()
			if tt.toBackendModifier != nil {
				toBackend = tt.toBackendModifier(toBackend.(*net.TCPConn))
			}
			toBackend = &halfCloseCheckingTCPConn{toBackend, false}

			// Requests and responses are sufficiently long to notice an
			// incomplete read.
			request := bytes.Repeat([]byte("q"), 1<<20)
			response := bytes.Repeat([]byte("r"), 1<<20)
			errOnBackend := make(chan error, 1)
			go tt.backend(backend, errOnBackend, request, response)

			// Create a "client" to receive a connection from.
			client, toClient, cleanupClient := makePeer()
			defer cleanupClient()
			if tt.toClientModifier != nil {
				toClient = tt.toClientModifier(toClient.(*net.TCPConn))
			}
			errOnClient := make(chan error, 1)
			go tt.client(client, errOnClient, request, response)

			err := Pipe(toBackend, toClient)
			gotError := err != nil
			if gotError {
				t.Logf("PipeTCP: %v", err)
			}
			if gotError != tt.wantPipeError {
				t.Errorf("PipeTCP: wanted error=%v, got=%v", tt.wantPipeError, gotError)
			}

			for range 2 {
				select {
				case err := <-errOnClient:
					gotError := err != nil
					if gotError {
						t.Logf("client: %v", err)
					}
					if gotError != tt.wantClientError {
						t.Errorf("client: wanted error=%v, got %v", tt.wantClientError, gotError)
					}
				case err := <-errOnBackend:
					gotError := err != nil
					if gotError {
						t.Logf("backend: %v", err)
					}
					if gotError != tt.wantBackendError {
						t.Errorf("client: wanted error=%v, got %v", tt.wantBackendError, gotError)
					}
				case <-time.After(5 * time.Second):
					t.Errorf("timed out waiting for peers to finish")
				}
			}

			if hc, ok := toBackend.(*halfCloseCheckingTCPConn); ok {
				if hc.halfClosed != tt.wantHalfClosed {
					t.Errorf("conn to backend: want halfClosed %v, got %v", tt.wantHalfClosed, hc.halfClosed)
				}
			}
		})
	}
}
