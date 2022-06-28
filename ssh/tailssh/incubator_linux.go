// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

package tailssh

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/godbus/dbus/v5"
	"tailscale.com/types/logger"
	"tailscale.com/version/distro"
)

func init() {
	ptyName = ptyNameLinux
	maybeStartLoginSession = maybeStartLoginSessionLinux
}

func ptyNameLinux(f *os.File) (string, error) {
	var n uint32
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n)))
	if e != 0 {
		return "", e
	}
	return fmt.Sprintf("pts/%d", n), nil
}

// callLogin1 invokes the provided method of the "login1" service over D-Bus.
// https://www.freedesktop.org/software/systemd/man/org.freedesktop.login1.html
func callLogin1(method string, flags dbus.Flags, args ...any) (*dbus.Call, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		// DBus probably not running.
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	name, objectPath := "org.freedesktop.login1", "/org/freedesktop/login1"
	obj := conn.Object(name, dbus.ObjectPath(objectPath))
	call := obj.CallWithContext(ctx, method, flags, args...)
	if call.Err != nil {
		return nil, call.Err
	}
	return call, nil
}

// createSessionArgs is a wrapper struct for the Login1.Manager.CreateSession args.
// The CreateSession API arguments and response types are defined here:
// https://www.freedesktop.org/software/systemd/man/org.freedesktop.login1.html
type createSessionArgs struct {
	uid        uint32     // User ID being logged in.
	pid        uint32     // Process ID for the session, 0 means current process.
	service    string     // Service creating the session.
	typ        string     // Type of login (oneof unspecified, tty, x11).
	class      string     // Type of session class (oneof user, greeter, lock-screen).
	desktop    string     // the desktop environment.
	seat       string     // the seat this session belongs to, empty otherwise.
	vtnr       uint32     // the virtual terminal number of the session if there is any, 0 otherwise.
	tty        string     // the kernel TTY path of the session if this is a text login, empty otherwise.
	display    string     // the X11 display name if this is a graphical login, empty otherwise.
	remote     bool       // whether the session is remote.
	remoteUser string     // the remote user if this is a remote session, empty otherwise.
	remoteHost string     // the remote host if this is a remote session, empty otherwise.
	properties []struct { // This is unused and exists just to make the marshaling work
		S string
		V dbus.Variant
	}
}

func (a createSessionArgs) args() []any {
	return []any{
		a.uid,
		a.pid,
		a.service,
		a.typ,
		a.class,
		a.desktop,
		a.seat,
		a.vtnr,
		a.tty,
		a.display,
		a.remote,
		a.remoteUser,
		a.remoteHost,
		a.properties,
	}
}

// createSessionResp is a wrapper struct for the Login1.Manager.CreateSession response.
// The CreateSession API arguments and response types are defined here:
// https://www.freedesktop.org/software/systemd/man/org.freedesktop.login1.html
type createSessionResp struct {
	sessionID   string
	objectPath  dbus.ObjectPath
	runtimePath string
	fifoFD      dbus.UnixFD
	uid         uint32
	seatID      string
	vtnr        uint32
	existing    bool // whether a new session was created.
}

// createSession creates a tty user login session for the provided uid.
func createSession(uid uint32, remoteUser, remoteHost, tty string) (createSessionResp, error) {
	a := createSessionArgs{
		uid:        uid,
		service:    "tailscaled",
		typ:        "tty",
		class:      "user",
		tty:        tty,
		remote:     true,
		remoteUser: remoteUser,
		remoteHost: remoteHost,
	}

	call, err := callLogin1("org.freedesktop.login1.Manager.CreateSession", 0, a.args()...)
	if err != nil {
		return createSessionResp{}, err
	}

	return createSessionResp{
		sessionID:   call.Body[0].(string),
		objectPath:  call.Body[1].(dbus.ObjectPath),
		runtimePath: call.Body[2].(string),
		fifoFD:      call.Body[3].(dbus.UnixFD),
		uid:         call.Body[4].(uint32),
		seatID:      call.Body[5].(string),
		vtnr:        call.Body[6].(uint32),
		existing:    call.Body[7].(bool),
	}, nil
}

// releaseSession releases the session identified by sessionID.
func releaseSession(sessionID string) error {
	// https://www.freedesktop.org/software/systemd/man/org.freedesktop.login1.html
	_, err := callLogin1("org.freedesktop.login1.Manager.ReleaseSession", dbus.FlagNoReplyExpected, sessionID)
	return err
}

// maybeStartLoginSessionLinux is the linux implementation of maybeStartLoginSession.
func maybeStartLoginSessionLinux(logf logger.Logf, ia incubatorArgs) (func() error, error) {
	if os.Geteuid() != 0 {
		return nil, nil
	}
	logf("starting session for user %d", ia.uid)
	// The only way we can actually start a new session is if we are
	// running outside one and are root, which is typically the case
	// for systemd managed tailscaled.
	resp, err := createSession(uint32(ia.uid), ia.remoteUser, ia.remoteIP, ia.ttyName)
	if err != nil {
		// TODO(maisem): figure out if we are running in a session.
		// We can look at the DBus GetSessionByPID API.
		// https://www.freedesktop.org/software/systemd/man/org.freedesktop.login1.html
		// For now best effort is fine.
		logf("ssh: failed to CreateSession for user %q (%d) %v", ia.localUser, ia.uid, err)
		return nil, nil
	}
	os.Setenv("DBUS_SESSION_BUS_ADDRESS", fmt.Sprintf("unix:path=%v/bus", resp.runtimePath))
	if !resp.existing {
		return func() error {
			return releaseSession(resp.sessionID)
		}, nil
	}
	return nil, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (ia *incubatorArgs) loginArgs() []string {
	if distro.Get() == distro.Arch && !fileExists("/etc/pam.d/remote") {
		// See https://github.com/tailscale/tailscale/issues/4924
		//
		// Arch uses a different login binary that makes the -h flag set the PAM
		// service to "remote". So if they don't have that configured, don't
		// pass -h.
		return []string{ia.loginCmdPath, "-f", ia.localUser, "-p"}
	}
	return []string{ia.loginCmdPath, "-f", ia.localUser, "-h", ia.remoteIP, "-p"}
}

func setGroups(groupIDs []int) error {
	return syscall.Setgroups(groupIDs)
}
