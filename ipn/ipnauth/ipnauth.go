// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ipnauth controls access to the LocalAPI.
package ipnauth

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"syscall"

	"inet.af/peercred"
	"tailscale.com/net/netstat"
	"tailscale.com/safesocket"
	"tailscale.com/types/logger"
	"tailscale.com/util/groupmember"
	"tailscale.com/util/pidowner"
	"tailscale.com/util/winutil"
	"tailscale.com/version/distro"
)

// ConnIdentity represents the owner of a localhost TCP or unix socket connection
// connecting to the LocalAPI.
type ConnIdentity struct {
	conn       net.Conn
	notWindows bool // runtime.GOOS != "windows"

	// Fields used when NotWindows:
	isUnixSock bool            // Conn is a *net.UnixConn
	creds      *peercred.Creds // or nil

	// Used on Windows:
	// TODO(bradfitz): merge these into the peercreds package and
	// use that for all.
	pid    int
	userID string
	user   *user.User
}

// UserID returns the local machine's userid of the connection.
//
// It's suitable for passing to LookupUserFromID (os/user.LookupId) on any
// operating system.
//
// TODO(bradfitz): it currently returns an empty string on everything
// but Windows. We should make it return the actual uid also on all supported
// peercred platforms from the creds if non-nil.
func (ci *ConnIdentity) UserID() string { return ci.userID }

func (ci *ConnIdentity) User() *user.User       { return ci.user }
func (ci *ConnIdentity) Pid() int               { return ci.pid }
func (ci *ConnIdentity) IsUnixSock() bool       { return ci.isUnixSock }
func (ci *ConnIdentity) NotWindows() bool       { return ci.notWindows }
func (ci *ConnIdentity) Creds() *peercred.Creds { return ci.creds }

// GetConnIdentity returns the localhost TCP connection's identity information
// (pid, userid, user). If it's not Windows (for now), it returns a nil error
// and a ConnIdentity with NotWindows set true. It's only an error if we expected
// to be able to map it and couldn't.
func GetConnIdentity(logf logger.Logf, c net.Conn) (ci *ConnIdentity, err error) {
	ci = &ConnIdentity{conn: c}
	if runtime.GOOS != "windows" { // for now; TODO: expand to other OSes
		ci.notWindows = true
		_, ci.isUnixSock = c.(*net.UnixConn)
		ci.creds, _ = peercred.Get(c)
		return ci, nil
	}
	la, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		return ci, fmt.Errorf("parsing local address: %w", err)
	}
	ra, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return ci, fmt.Errorf("parsing local remote: %w", err)
	}
	if !la.Addr().IsLoopback() || !ra.Addr().IsLoopback() {
		return ci, errors.New("non-loopback connection")
	}
	tab, err := netstat.Get()
	if err != nil {
		return ci, fmt.Errorf("failed to get local connection table: %w", err)
	}
	pid := peerPid(tab.Entries, la, ra)
	if pid == 0 {
		return ci, errors.New("no local process found matching localhost connection")
	}
	ci.pid = pid
	uid, err := pidowner.OwnerOfPID(pid)
	if err != nil {
		var hint string
		if runtime.GOOS == "windows" {
			hint = " (WSL?)"
		}
		return ci, fmt.Errorf("failed to map connection's pid to a user%s: %w", hint, err)
	}
	ci.userID = uid
	u, err := LookupUserFromID(logf, uid)
	if err != nil {
		return ci, fmt.Errorf("failed to look up user from userid: %w", err)
	}
	ci.user = u
	return ci, nil
}

// LookupUserFromID is a wrapper around os/user.LookupId that works around some
// issues on Windows. On non-Windows platforms it's identical to user.LookupId.
func LookupUserFromID(logf logger.Logf, uid string) (*user.User, error) {
	u, err := user.LookupId(uid)
	if err != nil && runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(0x534)) {
		// The below workaround is only applicable when uid represents a
		// valid security principal. Omitting this check causes us to succeed
		// even when uid represents a deleted user.
		if !winutil.IsSIDValidPrincipal(uid) {
			return nil, err
		}

		logf("[warning] issue 869: os/user.LookupId failed; ignoring")
		// Work around https://github.com/tailscale/tailscale/issues/869 for
		// now. We don't strictly need the username. It's just a nice-to-have.
		// So make up a *user.User if their machine is broken in this way.
		return &user.User{
			Uid:      uid,
			Username: "unknown-user-" + uid,
			Name:     "unknown user " + uid,
		}, nil
	}
	return u, err
}

// IsReadonlyConn reports whether the connection should be considered read-only,
// meaning it's not allowed to change the state of the node.
//
// Read-only also means it's not allowed to access sensitive information, which
// admittedly doesn't follow from the name. Consider this "IsUnprivileged".
// Also, Windows doesn't use this. For Windows it always returns false.
//
// TODO(bradfitz): rename it? Also make Windows use this.
func (ci *ConnIdentity) IsReadonlyConn(operatorUID string, logf logger.Logf) bool {
	if runtime.GOOS == "windows" {
		// Windows doesn't need/use this mechanism, at least yet. It
		// has a different last-user-wins auth model.
		return false
	}
	const ro = true
	const rw = false
	if !safesocket.PlatformUsesPeerCreds() {
		return rw
	}
	creds := ci.creds
	if creds == nil {
		logf("connection from unknown peer; read-only")
		return ro
	}
	uid, ok := creds.UserID()
	if !ok {
		logf("connection from peer with unknown userid; read-only")
		return ro
	}
	if uid == "0" {
		logf("connection from userid %v; root has access", uid)
		return rw
	}
	if selfUID := os.Getuid(); selfUID != 0 && uid == strconv.Itoa(selfUID) {
		logf("connection from userid %v; connection from non-root user matching daemon has access", uid)
		return rw
	}
	if operatorUID != "" && uid == operatorUID {
		logf("connection from userid %v; is configured operator", uid)
		return rw
	}
	if yes, err := isLocalAdmin(uid); err != nil {
		logf("connection from userid %v; read-only; %v", uid, err)
		return ro
	} else if yes {
		logf("connection from userid %v; is local admin, has access", uid)
		return rw
	}
	logf("connection from userid %v; read-only", uid)
	return ro
}

func isLocalAdmin(uid string) (bool, error) {
	u, err := user.LookupId(uid)
	if err != nil {
		return false, err
	}
	var adminGroup string
	switch {
	case runtime.GOOS == "darwin":
		adminGroup = "admin"
	case distro.Get() == distro.QNAP:
		adminGroup = "administrators"
	default:
		return false, fmt.Errorf("no system admin group found")
	}
	return groupmember.IsMemberOfGroup(adminGroup, u.Username)
}

func peerPid(entries []netstat.Entry, la, ra netip.AddrPort) int {
	for _, e := range entries {
		if e.Local == ra && e.Remote == la {
			return e.Pid
		}
	}
	return 0
}
