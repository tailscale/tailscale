// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"go4.org/mem"
	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/util/lineread"
	"tailscale.com/version/distro"
)

// userMeta is a wrapper around *user.User with extra fields.
type userMeta struct {
	user.User

	// loginShellCached is the user's login shell, if known
	// at the time of userLookup.
	loginShellCached string
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

// userLookup is like os/user.Lookup but it returns a *userMeta wrapper
// around a *user.User with extra fields.
func userLookup(username string) (*userMeta, error) {
	if runtime.GOOS != "linux" {
		return userLookupStd(username)
	}

	// No getent on Gokrazy. So hard-code the login shell.
	if distro.Get() == distro.Gokrazy {
		um, err := userLookupStd(username)
		if err != nil {
			um.User = user.User{
				Uid:      "0",
				Gid:      "0",
				Username: "root",
				Name:     "Gokrazy",
				HomeDir:  "/",
			}
		}
		um.loginShellCached = "/tmp/serial-busybox/ash"
		return um, err
	}

	// On Linux, default to using "getent" to look up users so that
	// even with static tailscaled binaries without cgo (as we distribute),
	// we can still look up PAM/NSS users which the standard library's
	// os/user without cgo won't get (because of no libc hooks).
	// But if "getent" fails, userLookupGetent falls back to the standard
	// library anyway.
	return userLookupGetent(username)
}

func validUsername(uid string) bool {
	maxUid := 32
	if runtime.GOOS == "linux" {
		maxUid = 256
	}
	if len(uid) > maxUid || len(uid) == 0 {
		return false
	}
	for _, r := range uid {
		if r < ' ' || r == 0x7f || r == utf8.RuneError { // TODO(bradfitz): more?
			return false
		}
	}
	return true
}

func userLookupGetent(username string) (*userMeta, error) {
	// Do some basic validation before passing this string to "getent", even though
	// getent should do its own validation.
	if !validUsername(username) {
		return nil, errors.New("invalid username")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "getent", "passwd", username).Output()
	if err != nil {
		log.Printf("error calling getent for user %q: %v", username, err)
		return userLookupStd(username)
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
		loginShellCached: f[6],
	}
	return um, nil
}

func userLookupStd(username string) (*userMeta, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return nil, err
	}
	return &userMeta{User: *u}, nil
}

func (u *userMeta) LoginShell() string {
	if u.loginShellCached != "" {
		// This field should be populated on Linux, at least, because
		// func userLookup on Linux uses "getent" to look up the user
		// and that populates it.
		return u.loginShellCached
	}
	switch runtime.GOOS {
	case "darwin":
		// Note: /Users/username is key, and not the same as u.HomeDir.
		out, _ := exec.Command("dscl", ".", "-read", filepath.Join("/Users", u.Username), "UserShell").Output()
		// out is "UserShell: /bin/bash"
		s, ok := strings.CutPrefix(string(out), "UserShell: ")
		if ok {
			return strings.TrimSpace(s)
		}
	}
	if e := os.Getenv("SHELL"); e != "" {
		return e
	}
	return "/bin/sh"
}

// defaultPathTmpl specifies the default PATH template to use for new sessions.
//
// If empty, a default value is used based on the OS & distro to match OpenSSH's
// usually-hardcoded behavior. (see
// https://github.com/tailscale/tailscale/issues/5285 for background).
//
// The template may contain @{HOME} or @{PAM_USER} which expand to the user's
// home directory and username, respectively. (PAM is not used, despite the
// name)
var defaultPathTmpl = envknob.RegisterString("TAILSCALE_SSH_DEFAULT_PATH")

func defaultPathForUser(u *user.User) string {
	if s := defaultPathTmpl(); s != "" {
		return expandDefaultPathTmpl(s, u)
	}
	isRoot := u.Uid == "0"
	switch distro.Get() {
	case distro.Debian:
		hi := hostinfo.New()
		if hi.Distro == "ubuntu" {
			// distro.Get's Debian includes Ubuntu. But see if it's actually Ubuntu.
			// Ubuntu doesn't empirically seem to distinguish between root and non-root for the default.
			// And it includes /snap/bin.
			return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"
		}
		if isRoot {
			return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
		}
		return "/usr/local/bin:/usr/bin:/bin:/usr/bn/games"
	case distro.NixOS:
		return defaultPathForUserOnNixOS(u)
	}
	if isRoot {
		return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	return "/usr/local/bin:/usr/bin:/bin"
}

func defaultPathForUserOnNixOS(u *user.User) string {
	var path string
	lineread.File("/etc/pam/environment", func(lineb []byte) error {
		if v := pathFromPAMEnvLine(lineb, u); v != "" {
			path = v
			return io.EOF // stop iteration
		}
		return nil
	})
	return path
}

func pathFromPAMEnvLine(line []byte, u *user.User) (path string) {
	if !mem.HasPrefix(mem.B(line), mem.S("PATH")) {
		return ""
	}
	rest := strings.TrimSpace(strings.TrimPrefix(string(line), "PATH"))
	if quoted, ok := strings.CutPrefix(rest, "DEFAULT="); ok {
		if path, err := strconv.Unquote(quoted); err == nil {
			return expandDefaultPathTmpl(path, u)
		}
	}
	return ""
}

func expandDefaultPathTmpl(t string, u *user.User) string {
	p := strings.NewReplacer(
		"@{HOME}", u.HomeDir,
		"@{PAM_USER}", u.Username,
	).Replace(t)
	if strings.Contains(p, "@{") {
		// If there are unknown expansions, conservatively fail closed.
		return ""
	}
	return p
}
