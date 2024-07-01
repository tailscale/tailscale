//go:build glidertests

package ssh

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gossh "github.com/tailscale/golang-x-crypto/ssh"
)

var sampleServerResponse = []byte("Hello world")

func sampleTCPSocketServer() net.Listener {
	l := newLocalTCPListener()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		conn.Write(sampleServerResponse)
		conn.Close()
	}()

	return l
}

func newTestSessionWithForwarding(t *testing.T, forwardingEnabled bool) (net.Listener, *gossh.Client, func()) {
	l := sampleTCPSocketServer()

	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {},
		LocalPortForwardingCallback: func(ctx Context, destinationHost string, destinationPort uint32) bool {
			addr := net.JoinHostPort(destinationHost, strconv.FormatInt(int64(destinationPort), 10))
			if addr != l.Addr().String() {
				panic("unexpected destinationHost: " + addr)
			}
			return forwardingEnabled
		},
	}, nil)

	return l, client, func() {
		cleanup()
		l.Close()
	}
}

func TestLocalPortForwardingWorks(t *testing.T) {
	t.Parallel()

	l, client, cleanup := newTestSessionWithForwarding(t, true)
	defer cleanup()

	conn, err := client.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("Error connecting to %v: %v", l.Addr().String(), err)
	}
	result, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, sampleServerResponse) {
		t.Fatalf("result = %#v; want %#v", result, sampleServerResponse)
	}
}

func TestLocalPortForwardingRespectsCallback(t *testing.T) {
	t.Parallel()

	l, client, cleanup := newTestSessionWithForwarding(t, false)
	defer cleanup()

	_, err := client.Dial("tcp", l.Addr().String())
	if err == nil {
		t.Fatalf("Expected error connecting to %v but it succeeded", l.Addr().String())
	}
	if !strings.Contains(err.Error(), "port forwarding is disabled") {
		t.Fatalf("Expected permission error but got %#v", err)
	}
}

func TestReverseTCPForwardingWorks(t *testing.T) {
	t.Parallel()

	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {},
		ReversePortForwardingCallback: func(ctx Context, bindHost string, bindPort uint32) bool {
			if bindHost != "127.0.0.1" {
				panic("unexpected bindHost: " + bindHost)
			}
			if bindPort != 0 {
				panic("unexpected bindPort: " + strconv.Itoa(int(bindPort)))
			}
			return true
		},
	}, nil)
	defer cleanup()

	l, err := client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on a random TCP port over SSH: %v", err)
	}
	defer l.Close()
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		conn.Write(sampleServerResponse)
		conn.Close()
	}()

	// Dial the listener that should've been created by the server.
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("Error connecting to %v: %v", l.Addr().String(), err)
	}
	result, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, sampleServerResponse) {
		t.Fatalf("result = %#v; want %#v", result, sampleServerResponse)
	}

	// Close the listener and make sure that the port is no longer in use.
	err = l.Close()
	if err != nil {
		t.Fatalf("failed to close remote listener: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	var d net.Dialer
	_, err = d.DialContext(ctx, "tcp", l.Addr().String())
	if err == nil {
		t.Fatalf("expected error connecting to %v but it succeeded", l.Addr().String())
	}
}

func TestReverseTCPForwardingRespectsCallback(t *testing.T) {
	t.Parallel()

	var called int64
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {},
		ReversePortForwardingCallback: func(ctx Context, bindHost string, bindPort uint32) bool {
			atomic.AddInt64(&called, 1)
			if bindHost != "127.0.0.1" {
				panic("unexpected bindHost: " + bindHost)
			}
			if bindPort != 0 {
				panic("unexpected bindPort: " + strconv.Itoa(int(bindPort)))
			}
			return false
		},
	}, nil)
	defer cleanup()

	_, err := client.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		t.Fatalf("Expected error listening on random port but it succeeded")
	}

	if atomic.LoadInt64(&called) != 1 {
		t.Fatalf("Expected callback to be called once but it was called %d times", called)
	}
}
