// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9

package tailssh

import (
	"bytes"
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
	"tailscale.com/util/mak"
	"tailscale.com/util/osuser"
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
	return osuser.GetGroupIds(&u.User)
}

// userLookup is like os/user.Lookup but it returns a *userMeta wrapper
// around a *user.User with extra fields.
func userLookup(username string) (*userMeta, error) {
	u, s, err := osuser.LookupByUsernameWithShell(username)
	if err != nil {
		return nil, err
	}

	return &userMeta{User: *u, loginShellCached: s}, nil
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

func defaultPathForUser(u *user.User) string {
	if s := defaultPathTmpl(); s != "" {
		return expandDefaultPathTmpl(s, u)
	}
	if runtime.GOOS == "plan9" {
		return "/bin"
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
		return "/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
	case distro.NixOS:
		return defaultPathForUserOnNixOS(u)
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

// runLocaleCommand runs the "locale" command and returns its output. It's a
// variable so it can be overridden in tests.
var runLocaleCommand = func() ([]byte, error) {
	return exec.Command("locale").Output()
}

var sshDisableLocale = envknob.RegisterBool("TS_SSH_DISABLE_LOCALE")

// readLocale returns the default LANG and LC_* environment variables to use
// for new sessions, if they can be discovered from the system. The fs argument
// is used to read configuration files, and may be os.DirFS("/") or a test FS.
// The returned map is from variable name to value (e.g. "LANG" => "en_US.UTF-8").
//
// A nil map means no defaults found or locale support is disabled by envknob.
func readLocale(root *os.Root) (vars map[string]string) {
	if sshDisableLocale() {
		return nil
	}

	// First off, if we have a default LANG set in a system-wide
	// configuration file, use that. Note that we intentionally don't have
	// the leading '/' prefix here since that's added by the Root.
	for _, fpath := range []string{
		"etc/locale.conf",
		"etc/default/locale",
		"etc/environment",
	} {
		fbytes, err := root.ReadFile(fpath)
		if err != nil {
			continue
		}

		for lineb := range lineiter.Bytes(fbytes) {
			k, v, ok := bytes.Cut(lineb, []byte("="))
			if !ok {
				continue
			}
			v = bytes.TrimSpace(v)
			if bytes.Equal(k, []byte("LANG")) || bytes.HasPrefix(k, []byte("LC_")) && len(v) > 0 {
				ks := string(k)
				if _, found := vars[ks]; !found {
					mak.Set(&vars, ks, string(v))
				}
			}
		}
	}

	// Next, if we're on a system with the "locale" command, try that.
	out, err := runLocaleCommand()
	if err != nil {
		return vars
	}
	for line := range lineiter.Bytes(out) {
		k, v, ok := bytes.Cut(line, []byte("="))
		if !ok {
			continue
		}
		v = bytes.TrimSpace(v)
		if bytes.Equal(k, []byte("LANG")) || bytes.HasPrefix(k, []byte("LC_")) && len(v) > 0 {
			ks := string(k)
			if _, found := vars[ks]; !found {
				mak.Set(&vars, ks, string(v))
			}
		}
	}

	return vars
}
