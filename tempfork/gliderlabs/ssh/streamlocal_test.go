//go:build glidertests

package ssh

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	gossh "github.com/tailscale/golang-x-crypto/ssh"
)

// tempDirUnixSocket returns a temporary directory that can safely hold unix
// sockets.
//
// On all platforms other than darwin this just returns t.TempDir(). On darwin
// we manually make a temporary directory in /tmp because t.TempDir() returns a
// very long directory name, and the path length limit for Unix sockets on
// darwin is 104 characters.
func tempDirUnixSocket(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "darwin" {
		testName := strings.ReplaceAll(t.Name(), "/", "_")
		dir, err := os.MkdirTemp("/tmp", fmt.Sprintf("gliderlabs-ssh-test-%s-", testName))
		if err != nil {
			t.Fatalf("create temp dir for test: %v", err)
		}

		t.Cleanup(func() {
			err := os.RemoveAll(dir)
			if err != nil {
				t.Errorf("remove temp dir %s: %v", dir, err)
			}
		})
		return dir
	}

	return t.TempDir()
}

func newLocalUnixListener(t *testing.T) net.Listener {
	path := filepath.Join(tempDirUnixSocket(t), "socket.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("failed to listen on a unix socket %q: %v", path, err)
	}
	return l
}

func sampleUnixSocketServer(t *testing.T) net.Listener {
	l := newLocalUnixListener(t)

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

func newTestSessionWithUnixForwarding(t *testing.T, forwardingEnabled bool) (net.Listener, *gossh.Client, func()) {
	l := sampleUnixSocketServer(t)

	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {},
		LocalUnixForwardingCallback: func(ctx Context, socketPath string) bool {
			if socketPath != l.Addr().String() {
				panic("unexpected socket path: " + socketPath)
			}
			return forwardingEnabled
		},
	}, nil)

	return l, client, func() {
		cleanup()
		l.Close()
	}
}

func TestLocalUnixForwardingWorks(t *testing.T) {
	t.Parallel()

	l, client, cleanup := newTestSessionWithUnixForwarding(t, true)
	defer cleanup()

	conn, err := client.Dial("unix", l.Addr().String())
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

func TestLocalUnixForwardingRespectsCallback(t *testing.T) {
	t.Parallel()

	l, client, cleanup := newTestSessionWithUnixForwarding(t, false)
	defer cleanup()

	_, err := client.Dial("unix", l.Addr().String())
	if err == nil {
		t.Fatalf("Expected error connecting to %v but it succeeded", l.Addr().String())
	}
	if !strings.Contains(err.Error(), "unix forwarding is disabled") {
		t.Fatalf("Expected permission error but got %#v", err)
	}
}

func TestReverseUnixForwardingWorks(t *testing.T) {
	t.Parallel()

	remoteSocketPath := filepath.Join(tempDirUnixSocket(t), "remote.sock")

	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {},
		ReverseUnixForwardingCallback: func(ctx Context, socketPath string) bool {
			if socketPath != remoteSocketPath {
				panic("unexpected socket path: " + socketPath)
			}
			return true
		},
	}, nil)
	defer cleanup()

	l, err := client.ListenUnix(remoteSocketPath)
	if err != nil {
		t.Fatalf("failed to listen on a unix socket over SSH %q: %v", remoteSocketPath, err)
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
	conn, err := net.Dial("unix", remoteSocketPath)
	if err != nil {
		t.Fatalf("Error connecting to %v: %v", remoteSocketPath, err)
	}
	result, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, sampleServerResponse) {
		t.Fatalf("result = %#v; want %#v", result, sampleServerResponse)
	}

	// Close the listener and make sure that the Unix socket is gone.
	err = l.Close()
	if err != nil {
		t.Fatalf("failed to close remote listener: %v", err)
	}
	_, err = os.Stat(remoteSocketPath)
	if err == nil && !os.IsNotExist(err) {
		t.Fatalf("expected remote socket to be gone but it still exists: %v", err)
	}
}

func TestReverseUnixForwardingRespectsCallback(t *testing.T) {
	t.Parallel()

	remoteSocketPath := filepath.Join(tempDirUnixSocket(t), "remote.sock")

	var called int64
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {},
		ReverseUnixForwardingCallback: func(ctx Context, socketPath string) bool {
			atomic.AddInt64(&called, 1)
			if socketPath != remoteSocketPath {
				panic("unexpected socket path: " + socketPath)
			}
			return false
		},
	}, nil)
	defer cleanup()

	_, err := client.ListenUnix(remoteSocketPath)
	if err == nil {
		t.Fatalf("Expected error listening on %q but it succeeded", remoteSocketPath)
	}

	if atomic.LoadInt64(&called) != 1 {
		t.Fatalf("Expected callback to be called once but it was called %d times", called)
	}
}
