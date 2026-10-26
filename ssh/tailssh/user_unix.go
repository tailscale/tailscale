// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9

package tailssh

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"go4.org/mem"
	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/util/lineiter"
	"tailscale.com/util/osuser"
	"tailscale.com/version/distro"
)

// GroupIds returns the list of group IDs that the user is a member of.
func (u *userMeta) GroupIds() ([]string, error) {
	return osuser.GetGroupIds(&u.User)
}

// isRootUser reports whether u is the superuser.
func isRootUser(u *userMeta) bool {
	if u.Username == "root" {
		return true
	}
	// Compare the uid numerically: a non-canonical uid like "00" also
	// denotes root, and must not bypass the non-root checks that later
	// parse the uid numerically (e.g. the incubator's --uid). Non-numeric
	// uids keep the previous string behavior (not root).
	if uid, err := strconv.ParseInt(u.Uid, 0, strconv.IntSize); err == nil {
		return uid == 0
	}
	return false
}

func (u *userMeta) LoginShell() string {
	if runtime.GOOS == "plan9" {
		return "/bin/rc"
	}
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

func defaultPathForUser(u *userMeta) string {
	if s := defaultPathTmpl(); s != "" {
		return expandDefaultPathTmpl(s, &u.User)
	}
	if runtime.GOOS == "plan9" {
		return "/bin"
	}
	isRoot := isRootUser(u)
	switch distro.Get() {
	case distro.Debian, distro.Crostini:
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
		return "/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
	case distro.NixOS:
		return defaultPathForUserOnNixOS(&u.User)
	}
	if isRoot {
		return "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	return "/usr/local/bin:/usr/bin:/bin"
}

func defaultPathForUserOnNixOS(u *user.User) string {
	for lr := range lineiter.File("/etc/pam/environment") {
		lineb, err := lr.Value()
		if err != nil {
			return ""
		}
		if v := pathFromPAMEnvLine(lineb, u); v != "" {
			return v
		}
	}
	return ""
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
