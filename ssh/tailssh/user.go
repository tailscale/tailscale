// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"context"
	"errors"
	"log"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"tailscale.com/version/distro"
)

// userMeta is a wrapper around *user.User with extra fields.
type userMeta struct {
	user.User

	// LoginShell is the user's login shell.
	LoginShell string
}

// GroupIds returns the list of group IDs that the user is a member of.
func (u *userMeta) GroupIds() ([]string, error) {
	if runtime.GOOS == "linux" && distro.Get() == distro.Gokrazy {
		// Gokrazy is a single-user appliance with ~no userspace.
		// There aren't users to look up (no /etc/passwd, etc)
		// so rather than fail below, just hardcode root.
		// TODO(bradfitz): fix os/user upstream instead?
		return []string{"0"}, nil
	}
	return u.User.GroupIds()
}

// userLookup is like os/user.LookupId but it returns a *userMeta wrapper
// around a *user.User with extra fields.
func userLookup(uid string) (*userMeta, error) {
	if runtime.GOOS != "linux" {
		return userLookupStd(uid)
	}

	// No getent on Gokrazy. So hard-code the login shell.
	if distro.Get() == distro.Gokrazy {
		um, err := userLookupStd(uid)
		if err == nil {
			um.LoginShell = "/tmp/serial-busybox/ash"
		}
		return um, err
	}

	// On Linux, default to using "getent" to look up users so that
	// even with static tailscaled binaries without cgo (as we distribute),
	// we can still look up PAM/NSS users which the standard library's
	// os/user without cgo won't get (because of no libc hooks).
	// But if "getent" fails, userLookupGetent falls back to the standard
	// library anyway.
	return userLookupGetent(uid)
}

func validUsername(uid string) bool {
	if len(uid) > 32 || len(uid) == 0 {
		return false
	}
	for _, r := range uid {
		if r < ' ' || r == 0x7f || r == utf8.RuneError { // TODO(bradfitz): more?
			return false
		}
	}
	return true
}

func userLookupGetent(uid string) (*userMeta, error) {
	// Do some basic validation before passing this string to "getent", even though
	// getent should do its own validation.
	if !validUsername(uid) {
		return nil, errors.New("invalid username")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "getent", "passwd", uid).Output()
	if err != nil {
		log.Printf("error calling getent for user %q: %v", uid, err)
		return userLookupStd(uid)
	}
	// output is "alice:x:1001:1001:Alice Smith,,,:/home/alice:/bin/bash"
	f := strings.SplitN(strings.TrimSpace(string(out)), ":", 10)
	for len(f) < 7 {
		f = append(f, "")
	}
	um := &userMeta{
		User: user.User{
			Username: f[0],
			Uid:      f[2],
			Gid:      f[3],
			Name:     f[4],
			HomeDir:  f[5],
		},
		LoginShell: f[6],
	}
	return um, nil
}

func userLookupStd(uid string) (*userMeta, error) {
	u, err := user.LookupId(uid)
	if err != nil {
		return nil, err
	}
	return &userMeta{User: *u}, nil
}
