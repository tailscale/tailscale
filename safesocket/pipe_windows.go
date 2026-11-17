// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package safesocket

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go pipe_windows.go

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/tailscale/go-winio"
	"golang.org/x/sys/windows"
)

func connect(ctx context.Context, path string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	// We use the identification impersonation level so that tailscaled may
	// obtain information about our token for access control purposes.
	return winio.DialPipeAccessImpLevel(ctx, path, windows.GENERIC_READ|windows.GENERIC_WRITE, winio.PipeImpLevelIdentification)
}

// connectCurrentUser connects to the pipe at path and then verifies that the
// pipe could only have been created, and can only be served, by the current
// user, closing the connection and returning an error if not.
func connectCurrentUser(ctx context.Context, path string) (net.Conn, error) {
	c, err := ConnectContext(ctx, path)
	if err != nil {
		return nil, err
	}
	if err := checkPipeExclusiveToCurrentUser(c); err != nil {
		c.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// checkPipeExclusiveToCurrentUser reports an error unless the named pipe c is
// connected to is owned by the current user and its DACL grants access to no
// one but the current user.
//
// A named pipe name is shared by all of its instances, and a client connecting
// to the name is served by whichever instance is waiting. The first instance's
// security descriptor governs the rest: creating another instance needs
// FILE_CREATE_PIPE_INSTANCE, which the DACL grants along with write access.
// So the server on the other end of c is the current user's if and only if the
// pipe was created by the current user (the owner: only administrators may
// set an owner other than themselves) and no one else may create instances
// (the DACL). Checking the owner alone would let another user serve
// connections on a pipe the current user created with a permissive DACL.
func checkPipeExclusiveToCurrentUser(c net.Conn) error {
	pc, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return fmt.Errorf("unexpected pipe conn type %T", c)
	}
	me, err := currentUserSID()
	if err != nil {
		return err
	}
	// GENERIC_READ on the pipe includes READ_CONTROL, so we may read its
	// security descriptor.
	sd, err := windows.GetSecurityInfo(windows.Handle(pc.Fd()), windows.SE_KERNEL_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("getting the pipe's security descriptor: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("getting the pipe's owner: %w", err)
	}
	if !owner.Equals(me) {
		return fmt.Errorf("named pipe is owned by %v, not by the current user %v; refusing to talk to it", owner, me)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("getting the pipe's DACL: %w", err)
	}
	if dacl == nil {
		return errors.New("named pipe has no DACL, so any user may serve it; refusing to talk to it")
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("reading the pipe's DACL: %w", err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue // a deny ACE can't let anyone else in
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(me) {
			return fmt.Errorf("named pipe grants access to %v, not only to the current user %v, so another user could serve it; refusing to talk to it", sid, me)
		}
	}
	return nil
}

// windowsSDDL is the Security Descriptor set on the namedpipe.
// It provides read/write access to all users and the local system.
//
// It deliberately sets no owner or group: the creator becomes the owner.
// Naming the Administrators group as the owner, as this once did, made
// listening fail for a tailscaled run by a non-administrator, since only
// administrators may assign that SID as an owner.
const windowsSDDL = "D:P(A;;GWGR;;;BU)(A;;GWGR;;;SY)"

func init() {
	listenCurrentUserHook = listenCurrentUser
	connectCurrentUserHook = connectCurrentUser
}

func listen(path string) (net.Listener, error) {
	return listenSDDL(path, windowsSDDL)
}

// currentUserSID returns the SID of the user this process runs as.
func currentUserSID() (*windows.SID, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("getting the current user's SID: %w", err)
	}
	return tu.User.Sid, nil
}

// listenCurrentUser is like listen, but the pipe is explicitly owned by the
// current user, and only that user may open it.
//
// The owner is what a connecting client of the same user checks; see
// connectCurrentUser. Only administrators may set an owner other than
// themselves, so a pipe owned by user X was created by X or by an
// administrator.
func listenCurrentUser(path string) (net.Listener, error) {
	sid, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	sddl := fmt.Sprintf("O:%sD:P(A;;GWGR;;;%s)", sid, sid)
	return listenSDDL(path, sddl)
}

func listenSDDL(path, sddl string) (net.Listener, error) {
	lc, err := winio.ListenPipe(
		path,
		&winio.PipeConfig{
			SecurityDescriptor: sddl,
			InputBufferSize:    256 * 1024,
			OutputBufferSize:   256 * 1024,
		},
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) && strings.HasPrefix(strings.ToLower(path), `\\.\pipe\protectedprefix\administrators\`) {
			// Only administrators may create pipes under that prefix,
			// which is where tailscaled listens by default.
			return nil, fmt.Errorf("namedpipe.Listen: %w; creating a pipe under \\\\.\\pipe\\ProtectedPrefix\\Administrators requires running as an administrator; run elevated or pass --socket with another pipe name", err)
		}
		return nil, fmt.Errorf("namedpipe.Listen: %w", err)
	}
	return &winIOPipeListener{Listener: lc}, nil
}

// WindowsClientConn is an implementation of net.Conn that permits retrieval of
// the Windows access token associated with the connection's client. The
// embedded net.Conn must be a go-winio PipeConn.
type WindowsClientConn struct {
	winioPipeConn
	tokenOnce sync.Once
	token     windows.Token // or zero, if we couldn't obtain the client's token
	tokenErr  error
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

// CheckToken returns an error if the client user's access token could not be retrieved,
// for example when the client opens the pipe with an anonymous impersonation level.
//
// Deprecated: use [WindowsClientConn.Token] instead.
func (conn *WindowsClientConn) CheckToken() error {
	_, err := conn.getToken()
	return err
}

// getToken returns the Windows access token of the client user,
// or an error if the token could not be retrieved, for example
// when the client opens the pipe with an anonymous impersonation level.
//
// The connection retains ownership of the returned token handle;
// the caller must not close it.
//
// TODO(nickkhyl): Remove this, along with [WindowsClientConn.CheckToken],
// once [ipnauth.ConnIdentity] is removed in favor of [ipnauth.Actor].
func (conn *WindowsClientConn) getToken() (windows.Token, error) {
	conn.tokenOnce.Do(func() {
		conn.token, conn.tokenErr = clientUserAccessToken(conn.winioPipeConn)
	})
	return conn.token, conn.tokenErr
}

// Token returns the Windows access token of the client user,
// or an error if the token could not be retrieved, for example
// when the client opens the pipe with an anonymous impersonation level.
//
// The caller is responsible for closing the returned token handle.
func (conn *WindowsClientConn) Token() (windows.Token, error) {
	token, err := conn.getToken()
	if err != nil {
		return 0, err
	}

	var dupToken windows.Handle
	if err := windows.DuplicateHandle(
		windows.CurrentProcess(),
		windows.Handle(token),
		windows.CurrentProcess(),
		&dupToken,
		0,
		false,
		windows.DUPLICATE_SAME_ACCESS,
	); err != nil {
		return 0, err
	}
	return windows.Token(dupToken), nil
}

func (conn *WindowsClientConn) Close() error {
	// Either wait for any pending [WindowsClientConn.Token] calls to complete,
	// or ensure that the token will never be opened.
	conn.tokenOnce.Do(func() {
		conn.tokenErr = net.ErrClosed
	})
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
	return &WindowsClientConn{winioPipeConn: pipeConn}, nil
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
