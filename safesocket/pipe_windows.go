// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package safesocket

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go pipe_windows.go

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"time"

	"github.com/tailscale/go-winio"
	"golang.org/x/sys/windows"
)

func connect(s *ConnectionStrategy) (net.Conn, error) {
	dl := time.Now().Add(20 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), dl)
	defer cancel()
	// We use the identification impersonation level so that tailscaled may
	// obtain information about our token for access control purposes.
	return winio.DialPipeAccessImpLevel(ctx, s.path, windows.GENERIC_READ|windows.GENERIC_WRITE, winio.PipeImpLevelIdentification)
}

func setFlags(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET,
			syscall.SO_REUSEADDR, 1)
	})
}

// windowsSDDL is the Security Descriptor set on the namedpipe.
// It provides read/write access to all users and the local system.
// It is a var for testing, do not change this value.
var windowsSDDL = "O:BAG:BAD:PAI(A;OICI;GWGR;;;BU)(A;OICI;GWGR;;;SY)"

func listen(path string) (net.Listener, error) {
	lc, err := winio.ListenPipe(
		path,
		&winio.PipeConfig{
			SecurityDescriptor: windowsSDDL,
			InputBufferSize:    256 * 1024,
			OutputBufferSize:   256 * 1024,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("namedpipe.Listen: %w", err)
	}
	return &winIOPipeListener{Listener: lc}, nil
}

// WindowsClientConn is an implementation of net.Conn that permits retrieval of
// the Windows access token associated with the connection's client. The
// embedded net.Conn must be a go-winio PipeConn.
type WindowsClientConn struct {
	net.Conn
	token windows.Token
}

// winioPipeHandle is fulfilled by the underlying code implementing go-winio's
// PipeConn interface.
type winioPipeHandle interface {
	// Fd returns the Windows handle associated with the connection.
	Fd() uintptr
}

func resolvePipeHandle(c net.Conn) windows.Handle {
	wph, ok := c.(winioPipeHandle)
	if !ok {
		return 0
	}
	return windows.Handle(wph.Fd())
}

func (conn *WindowsClientConn) handle() windows.Handle {
	return resolvePipeHandle(conn.Conn)
}

// ClientPID returns the pid of conn's client, or else an error.
func (conn *WindowsClientConn) ClientPID() (int, error) {
	var pid uint32
	if err := getNamedPipeClientProcessId(conn.handle(), &pid); err != nil {
		return -1, fmt.Errorf("GetNamedPipeClientProcessId: %w", err)
	}
	return int(pid), nil
}

// Token returns the Windows access token of the client user.
func (conn *WindowsClientConn) Token() windows.Token {
	return conn.token
}

func (conn *WindowsClientConn) Close() error {
	if conn.token != 0 {
		conn.token.Close()
		conn.token = 0
	}
	return conn.Conn.Close()
}

type winIOPipeListener struct {
	net.Listener
}

func (lw *winIOPipeListener) Accept() (net.Conn, error) {
	conn, err := lw.Listener.Accept()
	if err != nil {
		return nil, err
	}

	token, err := clientUserAccessToken(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &WindowsClientConn{
		Conn:  conn,
		token: token,
	}, nil
}

func clientUserAccessToken(c net.Conn) (windows.Token, error) {
	h := resolvePipeHandle(c)
	if h == 0 {
		return 0, fmt.Errorf("not a windows handle: %T", c)
	}

	// Impersonation touches thread-local state, so we need to lock until the
	// client access token has been extracted.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := impersonateNamedPipeClient(h); err != nil {
		return 0, err
	}
	defer func() {
		// Revert the current thread's impersonation.
		if err := windows.RevertToSelf(); err != nil {
			panic(fmt.Errorf("could not revert impersonation: %w", err))
		}
	}()

	// Extract the client's access token from the thread-local state.
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, true, &token); err != nil {
		return 0, err
	}

	return token, nil
}

//sys getNamedPipeClientProcessId(h windows.Handle, clientPid *uint32) (err error) [int32(failretval)==0] = kernel32.GetNamedPipeClientProcessId
//sys impersonateNamedPipeClient(h windows.Handle) (err error) [int32(failretval)==0] = advapi32.ImpersonateNamedPipeClient
