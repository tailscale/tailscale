// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ipnauth controls access to the LocalAPI.
package ipnauth

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"inet.af/peercred"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/net/netstat"
	"tailscale.com/safesocket"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/groupmember"
	"tailscale.com/util/winutil"
	"tailscale.com/version/distro"
)

// ErrNotImplemented is returned by ConnIdentity.WindowsToken when it is not
// implemented for the current GOOS.
var ErrNotImplemented = errors.New("not implemented for GOOS=" + runtime.GOOS)

// WindowsToken represents the current security context of a Windows user.
type WindowsToken interface {
	io.Closer
	// EqualUIDs reports whether other refers to the same user ID as the receiver.
	EqualUIDs(other WindowsToken) bool
	// IsAdministrator reports whether the receiver is a member of the built-in
	// Administrators group, or else an error. Use IsElevated to determine whether
	// the receiver is actually utilizing administrative rights.
	IsAdministrator() (bool, error)
	// IsUID reports whether the receiver's user ID matches uid.
	IsUID(uid ipn.WindowsUserID) bool
	// UID returns the ipn.WindowsUserID associated with the receiver, or else
	// an error.
	UID() (ipn.WindowsUserID, error)
	// IsElevated reports whether the receiver is currently executing as an
	// elevated administrative user.
	IsElevated() bool
	// UserDir returns the special directory identified by folderID as associated
	// with the receiver. folderID must be one of the KNOWNFOLDERID values from
	// the x/sys/windows package, serialized as a stringified GUID.
	UserDir(folderID string) (string, error)
	// Username returns the user name associated with the receiver.
	Username() (string, error)
}

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
	pid int
}

// WindowsUserID returns the local machine's userid of the connection
// if it's on Windows. Otherwise it returns the empty string.
//
// It's suitable for passing to LookupUserFromID (os/user.LookupId) on any
// operating system.
func (ci *ConnIdentity) WindowsUserID() ipn.WindowsUserID {
	if envknob.GOOS() != "windows" {
		return ""
	}
	if tok, err := ci.WindowsToken(); err == nil {
		defer tok.Close()
		if uid, err := tok.UID(); err == nil {
			return uid
		}
	}
	// For Linux tests running as Windows:
	const isBroken = true // TODO(bradfitz,maisem): fix tests; this doesn't work yet
	if ci.creds != nil && !isBroken {
		if uid, ok := ci.creds.UserID(); ok {
			return ipn.WindowsUserID(uid)
		}
	}
	return ""
}

func (ci *ConnIdentity) Pid() int               { return ci.pid }
func (ci *ConnIdentity) IsUnixSock() bool       { return ci.isUnixSock }
func (ci *ConnIdentity) Creds() *peercred.Creds { return ci.creds }

var metricIssue869Workaround = clientmetric.NewCounter("issue_869_workaround")

// LookupUserFromID is a wrapper around os/user.LookupId that works around some
// issues on Windows. On non-Windows platforms it's identical to user.LookupId.
func LookupUserFromID(logf logger.Logf, uid string) (*user.User, error) {
	u, err := user.LookupId(uid)
	if err != nil && runtime.GOOS == "windows" {
		// See if uid resolves as a pseudo-user. Temporary workaround until
		// https://github.com/golang/go/issues/49509 resolves and ships.
		if u, err := winutil.LookupPseudoUser(uid); err == nil {
			return u, nil
		}

		// TODO(aaron): With LookupPseudoUser in place, I don't expect us to reach
		// this point anymore. Leaving the below workaround in for now to confirm
		// that pseudo-user resolution sufficiently handles this problem.

		// The below workaround is only applicable when uid represents a
		// valid security principal. Omitting this check causes us to succeed
		// even when uid represents a deleted user.
		if !winutil.IsSIDValidPrincipal(uid) {
			return nil, err
		}

		metricIssue869Workaround.Add(1)
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

// IsLocalAdmin reports whether the connected user has local administrative
// privileges on the host. This means root, or one of:
//
//   - Windows: member of the Administrators group
//   - macOS: member of the admin group
//   - Linux: member of any sudoers group (usually "sudo" or "wheel")
func (ci *ConnIdentity) IsLocalAdmin() (bool, error) {
	if ci.creds == nil {
		return false, nil
	}
	uid, ok := ci.creds.UserID()
	if !ok {
		return false, nil
	}
	if uid == "0" {
		return true, nil
	}
	return isLocalAdmin(uid)
}

func isLocalAdmin(uid string) (bool, error) {
	u, err := user.LookupId(uid)
	if err != nil {
		return false, err
	}
	var adminGroups []string
	switch {
	case runtime.GOOS == "darwin":
		adminGroups = []string{"admin"}
	case distro.Get() == distro.QNAP:
		adminGroups = []string{"administrators"}
	case runtime.GOOS == "linux":
		adminGroups, err = linuxSudoersGroups("/etc/sudoers")
		log.Printf("========= linuxSudoersGroups(etc/sudoers): %q %v", adminGroups, err)
		if err != nil {
			return false, err
		}
	default:
		return false, fmt.Errorf("no system admin group found")
	}
	return groupmember.IsMemberOfAnyGroup(u.Username, adminGroups...)
}

func peerPid(entries []netstat.Entry, la, ra netip.AddrPort) int {
	for _, e := range entries {
		if e.Local == ra && e.Remote == la {
			return e.Pid
		}
	}
	return 0
}

func linuxSudoersGroups(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// We're looking for lines like:
	//
	//  %wheel ALL=(ALL:ALL) ALL
	//  %sudo ALL=(ALL:ALL) ALL
	//
	// where group name after % is allowed to sudo as any user and run any
	// command. Membership in these groups is equivalent to local admin.
	s := bufio.NewScanner(f)
	var groups []string
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "@includedir ") {
			dir := strings.TrimPrefix(line, "@includedir ")
			paths, err := os.ReadDir(dir)
			if err != nil {
				return nil, err
			}
			for _, p := range paths {
				if !p.Type().IsRegular() {
					continue
				}
				incGroups, err := linuxSudoersGroups(filepath.Join(dir, p.Name()))
				log.Printf("========= linuxSudoersGroups(%q): %q %v", filepath.Join(dir, p.Name()), incGroups, err)
				if err != nil {
					return nil, err
				}
				groups = append(groups, incGroups...)
			}
			continue
		}
		if !strings.HasPrefix(line, "%") {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		if !slices.Contains([]string{"ALL=(ALL:ALL) ALL", "ALL=(ALL) ALL"}, parts[1]) {
			continue
		}
		group := strings.TrimPrefix(parts[0], "%")
		if group != "" {
			groups = append(groups, group)
		}
	}

	return groups, s.Err()
}
