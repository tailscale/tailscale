// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"fmt"
	"net"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
	"tailscale.com/ipn"
	"tailscale.com/safesocket"
	"tailscale.com/types/logger"
	"tailscale.com/util/winutil"
)

// GetConnIdentity extracts the identity information from the connection
// based on the user who owns the other end of the connection.
// If c is not backed by a named pipe, an error is returned.
func GetConnIdentity(logf logger.Logf, c net.Conn) (ci *ConnIdentity, err error) {
	ci = &ConnIdentity{conn: c, notWindows: false}
	wcc, ok := c.(*safesocket.WindowsClientConn)
	if !ok {
		return nil, fmt.Errorf("not a WindowsClientConn: %T", c)
	}
	ci.pid, err = wcc.ClientPID()
	if err != nil {
		return nil, err
	}
	return ci, nil
}

type token struct {
	t windows.Token
}

func (t *token) UID() (ipn.WindowsUserID, error) {
	sid, err := t.uid()
	if err != nil {
		return "", fmt.Errorf("failed to look up user from token: %w", err)
	}

	return ipn.WindowsUserID(sid.String()), nil
}

func (t *token) Username() (string, error) {
	sid, err := t.uid()
	if err != nil {
		return "", fmt.Errorf("failed to look up user from token: %w", err)
	}

	username, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return "", fmt.Errorf("failed to look up username from SID: %w", err)
	}

	return fmt.Sprintf(`%s\%s`, domain, username), nil
}

func (t *token) IsAdministrator() (bool, error) {
	baSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, err
	}

	isMember, err := t.t.IsMember(baSID)
	if err != nil {
		return false, err
	}
	if isMember {
		return true, nil
	}

	isLimited, err := winutil.IsTokenLimited(t.t)
	if err != nil || !isLimited {
		return false, err
	}

	// Try to obtain a linked token, and if present, check it.
	// (This should be the elevated token associated with limited UAC accounts.)
	linkedToken, err := t.t.GetLinkedToken()
	if err != nil {
		return false, err
	}
	defer linkedToken.Close()

	return linkedToken.IsMember(baSID)
}

func (t *token) IsElevated() bool {
	return t.t.IsElevated()
}

func (t *token) IsLocalSystem() bool {
	// https://web.archive.org/web/2024/https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
	const systemUID = ipn.WindowsUserID("S-1-5-18")
	return t.IsUID(systemUID)
}

func (t *token) UserDir(folderID string) (string, error) {
	guid, err := windows.GUIDFromString(folderID)
	if err != nil {
		return "", err
	}

	return t.t.KnownFolderPath((*windows.KNOWNFOLDERID)(unsafe.Pointer(&guid)), 0)
}

func (t *token) Close() error {
	if t.t == 0 {
		return nil
	}
	if err := t.t.Close(); err != nil {
		return err
	}
	t.t = 0
	runtime.SetFinalizer(t, nil)
	return nil
}

func (t *token) EqualUIDs(other WindowsToken) bool {
	if t != nil && other == nil || t == nil && other != nil {
		return false
	}
	ot, ok := other.(*token)
	if !ok {
		return false
	}
	if t == ot {
		return true
	}
	uid, err := t.uid()
	if err != nil {
		return false
	}
	oUID, err := ot.uid()
	if err != nil {
		return false
	}
	return uid.Equals(oUID)
}

func (t *token) uid() (*windows.SID, error) {
	tu, err := t.t.GetTokenUser()
	if err != nil {
		return nil, err
	}

	return tu.User.Sid, nil
}

func (t *token) IsUID(uid ipn.WindowsUserID) bool {
	tUID, err := t.UID()
	if err != nil {
		return false
	}

	return tUID == uid
}

// WindowsToken returns the WindowsToken representing the security context
// of the connection's client.
func (ci *ConnIdentity) WindowsToken() (WindowsToken, error) {
	var wcc *safesocket.WindowsClientConn
	var ok bool
	if wcc, ok = ci.conn.(*safesocket.WindowsClientConn); !ok {
		return nil, fmt.Errorf("not a WindowsClientConn: %T", ci.conn)
	}

	// We duplicate the token's handle so that the WindowsToken we return may have
	// a lifetime independent from the original connection.
	var h windows.Handle
	if err := windows.DuplicateHandle(
		windows.CurrentProcess(),
		windows.Handle(wcc.Token()),
		windows.CurrentProcess(),
		&h,
		0,
		false,
		windows.DUPLICATE_SAME_ACCESS,
	); err != nil {
		return nil, err
	}

	result := &token{t: windows.Token(h)}
	runtime.SetFinalizer(result, func(t *token) { t.Close() })
	return result, nil
}
