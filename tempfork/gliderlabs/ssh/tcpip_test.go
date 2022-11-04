//go:build glidertests

package ssh

import (
	"bytes"
	"net"
	"strconv"
	"strings"
	"testing"

	gossh "github.com/tailscale/golang-x-crypto/ssh"
)

var sampleServerResponse = []byte("Hello world")

func sampleSocketServer() net.Listener {
	l := newLocalListener()

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
	l := sampleSocketServer()

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
