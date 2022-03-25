//go:build glidertests
// +build glidertests

package ssh

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"

	gossh "github.com/tailscale/golang-x-crypto/ssh"
)

func newTestSessionWithOptions(t *testing.T, srv *Server, cfg *gossh.ClientConfig, options ...Option) (*gossh.Session, *gossh.Client, func()) {
	for _, option := range options {
		if err := srv.SetOption(option); err != nil {
			t.Fatal(err)
		}
	}
	return newTestSession(t, srv, cfg)
}

func TestPasswordAuth(t *testing.T) {
	t.Parallel()
	testUser := "testuser"
	testPass := "testpass"
	session, _, cleanup := newTestSessionWithOptions(t, &Server{
		Handler: func(s Session) {
			// noop
		},
	}, &gossh.ClientConfig{
		User: testUser,
		Auth: []gossh.AuthMethod{
			gossh.Password(testPass),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}, PasswordAuth(func(ctx Context, password string) bool {
		if ctx.User() != testUser {
			t.Fatalf("user = %#v; want %#v", ctx.User(), testUser)
		}
		if password != testPass {
			t.Fatalf("user = %#v; want %#v", password, testPass)
		}
		return true
	}))
	defer cleanup()
	if err := session.Run(""); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordAuthBadPass(t *testing.T) {
	t.Parallel()
	l := newLocalListener()
	srv := &Server{Handler: func(s Session) {}}
	srv.SetOption(PasswordAuth(func(ctx Context, password string) bool {
		return false
	}))
	go srv.serveOnce(l)
	_, err := gossh.Dial("tcp", l.Addr().String(), &gossh.ClientConfig{
		User: "testuser",
		Auth: []gossh.AuthMethod{
			gossh.Password("testpass"),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		if !strings.Contains(err.Error(), "unable to authenticate") {
			t.Fatal(err)
		}
	}
}

type wrappedConn struct {
	net.Conn
	written int32
}

func (c *wrappedConn) Write(p []byte) (n int, err error) {
	n, err = c.Conn.Write(p)
	atomic.AddInt32(&(c.written), int32(n))
	return
}

func TestConnWrapping(t *testing.T) {
	t.Parallel()
	var wrapped *wrappedConn
	session, _, cleanup := newTestSessionWithOptions(t, &Server{
		Handler: func(s Session) {
			// nothing
		},
	}, &gossh.ClientConfig{
		User: "testuser",
		Auth: []gossh.AuthMethod{
			gossh.Password("testpass"),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}, PasswordAuth(func(ctx Context, password string) bool {
		return true
	}), WrapConn(func(ctx Context, conn net.Conn) net.Conn {
		wrapped = &wrappedConn{conn, 0}
		return wrapped
	}))
	defer cleanup()
	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&(wrapped.written)) == 0 {
		t.Fatal("wrapped conn not written to")
	}
}
