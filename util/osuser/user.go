// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package osuser implements OS user lookup. It's a wrapper around os/user that
// works on non-cgo builds.
package osuser

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

// LookupByUIDWithShell is like os/user.LookupId but handles a few edge cases
// like gokrazy and non-cgo lookups, and returns the user shell. The user shell
// lookup is best-effort and may be empty.
func LookupByUIDWithShell(uid string) (u *user.User, shell string, err error) {
	return lookup(uid, user.LookupId, true)
}

// LookupByUsernameWithShell is like os/user.Lookup but handles a few edge
// cases like gokrazy and non-cgo lookups, and returns the user shell. The user
// shell lookup is best-effort and may be empty.
func LookupByUsernameWithShell(username string) (u *user.User, shell string, err error) {
	return lookup(username, user.Lookup, true)
}

// LookupByUID is like os/user.LookupId but handles a few edge cases like
// gokrazy and non-cgo lookups.
func LookupByUID(uid string) (*user.User, error) {
	u, _, err := lookup(uid, user.LookupId, false)
	return u, err
}

// LookupByUsername is like os/user.Lookup but handles a few edge cases like
// gokrazy and non-cgo lookups.
func LookupByUsername(username string) (*user.User, error) {
	u, _, err := lookup(username, user.Lookup, false)
	return u, err
}

// lookupStd is either user.Lookup or user.LookupId.
type lookupStd func(string) (*user.User, error)

func lookup(usernameOrUID string, std lookupStd, wantShell bool) (*user.User, string, error) {
	// Skip getent entirely on Non-Unix platforms that won't ever have it.
	// (Using HasPrefix for "wasip1", anticipating that WASI support will
	// move beyond "preview 1" some day.)
	if runtime.GOOS == "windows" || runtime.GOOS == "js" || runtime.GOARCH == "wasm" {
		u, err := std(usernameOrUID)
		return u, "", err
	}

	// No getent on Gokrazy. So hard-code the login shell.
	if distro.Get() == distro.Gokrazy {
		var shell string
		if wantShell {
			shell = "/tmp/serial-busybox/ash"
		}
		u, err := std(usernameOrUID)
		if err != nil {
			return &user.User{
				Uid:      "0",
				Gid:      "0",
				Username: "root",
				Name:     "Gokrazy",
				HomeDir:  "/",
			}, shell, nil
		}
		return u, shell, nil
	}

	// Start with getent if caller wants to get the user shell.
	if wantShell {
		return userLookupGetent(usernameOrUID, std)
	}
	// If shell is not required, try os/user.Lookup* first and only use getent
	// if that fails. This avoids spawning a child process when os/user lookup
	// succeeds.
	if u, err := std(usernameOrUID); err == nil {
		return u, "", nil
	}
	return userLookupGetent(usernameOrUID, std)
}

func checkGetentInput(usernameOrUID string) bool {
	maxUid := 32
	if runtime.GOOS == "linux" {
		maxUid = 256
	}
	if len(usernameOrUID) > maxUid || len(usernameOrUID) == 0 {
		return false
	}
	for _, r := range usernameOrUID {
		if r < ' ' || r == 0x7f || r == utf8.RuneError { // TODO(bradfitz): more?
			return false
		}
	}
	return true
}

// userLookupGetent uses "getent" to look up users so that even with static
// tailscaled binaries without cgo (as we distribute), we can still look up
// PAM/NSS users which the standard library's os/user without cgo won't get
// (because of no libc hooks). If "getent" fails, userLookupGetent falls back
// to the standard library.
func userLookupGetent(usernameOrUID string, std lookupStd) (*user.User, string, error) {
	// Do some basic validation before passing this string to "getent", even though
	// getent should do its own validation.
	if !checkGetentInput(usernameOrUID) {
		return nil, "", errors.New("invalid username or UID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "getent", "passwd", usernameOrUID).Output()
	if err != nil {
		log.Printf("error calling getent for user %q: %v", usernameOrUID, err)
		u, err := std(usernameOrUID)
		return u, "", err
	}
	// output is "alice:x:1001:1001:Alice Smith,,,:/home/alice:/bin/bash"
	f := strings.SplitN(strings.TrimSpace(string(out)), ":", 10)
	for len(f) < 7 {
		f = append(f, "")
	}
	var mandatoryFields = []int{0, 2, 3, 5}
	for _, v := range mandatoryFields {
		if f[v] == "" {
			log.Printf("getent for user %q returned invalid output: %q", usernameOrUID, out)
			u, err := std(usernameOrUID)
			return u, "", err
		}
	}
	return &user.User{
		Username: f[0],
		Uid:      f[2],
		Gid:      f[3],
		Name:     f[4],
		HomeDir:  f[5],
	}, f[6], nil
}
