// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package safesocket

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go pipe_windows.go

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/tailscale/go-winio"
	"golang.org/x/sys/windows"
)

func connect(path string) (net.Conn, error) {
	dl := time.Now().Add(20 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), dl)
	defer cancel()
	// We use the identification impersonation level so that tailscaled may
	// obtain information about our token for access control purposes.
	return winio.DialPipeAccessImpLevel(ctx, path, windows.GENERIC_READ|windows.GENERIC_WRITE, winio.PipeImpLevelIdentification)
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
	winioPipeConn
	token windows.Token
}

// winioPipeConn is a subset of the interface implemented by the go-winio's
// unexported *win32pipe type, as returned by go-winio's ListenPipe
// net.Listener's Accept method. This type is used in places where we really are
// assuming that specific unexported type and its Fd method.
type winioPipeConn interface {
	net.Conn
	// Fd returns the Windows handle associated with the connection.
	Fd() uintptr
}

func resolvePipeHandle(pc winioPipeConn) windows.Handle {
	return windows.Handle(pc.Fd())
}

func (conn *WindowsClientConn) handle() windows.Handle {
	return resolvePipeHandle(conn.winioPipeConn)
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
	return conn.winioPipeConn.Close()
}

// winIOPipeListener is a net.Listener that wraps a go-winio PipeListener and
// returns net.Conn values of type *WindowsClientConn with the associated
// windows.Token.
type winIOPipeListener struct {
	net.Listener // must be from winio.ListenPipe
}

func (lw *winIOPipeListener) Accept() (net.Conn, error) {
	conn, err := lw.Listener.Accept()
	if err != nil {
		return nil, err
	}

	pipeConn, ok := conn.(winioPipeConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("unexpected type %T from winio.ListenPipe listener (itself a %T)", conn, lw.Listener)
	}

	token, err := clientUserAccessToken(pipeConn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &WindowsClientConn{
		winioPipeConn: pipeConn,
		token:         token,
	}, nil
}

func clientUserAccessToken(pc winioPipeConn) (windows.Token, error) {
	h := resolvePipeHandle(pc)
	if h == 0 {
		return 0, fmt.Errorf("clientUserAccessToken failed to get handle from pipeConn %T", pc)
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
