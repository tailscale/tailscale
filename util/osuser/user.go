// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package osuser implements OS user lookup. It's a wrapper around os/user that
// works on non-cgo builds.
package osuser

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"os/user"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"
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

var execGetent = func(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "getent", args...).Output()
}

var execId = func(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "id", args...).CombinedOutput()
}

var getentDoubleDashSupported = sync.OnceValue(probeGetentDoubleDashSupport)

func lookup(usernameOrUID string, std lookupStd, wantShell bool) (*user.User, string, error) {
	// Skip getent entirely on Non-Unix platforms that won't ever have it.
	// (Using HasPrefix for "wasip1", anticipating that WASI support will
	// move beyond "preview 1" some day.)
	if runtime.GOOS == "windows" || runtime.GOOS == "js" || runtime.GOARCH == "wasm" || runtime.GOOS == "plan9" {
		var shell string
		if wantShell && runtime.GOOS == "plan9" {
			shell = "/bin/rc"
		}
		if runtime.GOOS == "plan9" {
			if u, err := user.Current(); err == nil {
				return u, shell, nil
			}
		}
		u, err := std(usernameOrUID)
		return u, shell, err
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

	if runtime.GOOS == "plan9" {
		return &user.User{
			Uid:      "0",
			Gid:      "0",
			Username: "glenda",
			Name:     "Glenda",
			HomeDir:  "/",
		}, "/bin/rc", nil
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

	// Leading dashes aren't valid for usernames.
	if strings.HasPrefix(usernameOrUID, "-") {
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
// to the standard library. If both fail, an explicit getent failure is
// preserved rather than turning a directory outage into an absent local user.
// getent exit 2 is treated as not found, though NSS may also report it during
// an outage; that case cannot be distinguished from account deletion.
func userLookupGetent(usernameOrUID string, std lookupStd) (*user.User, string, error) {
	// Do some basic validation before passing this string to "getent", even though
	// getent should do its own validation.
	if !checkGetentInput(usernameOrUID) {
		return nil, "", errors.New("invalid username or UID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	args := []string{"passwd"}
	// Append "--" only if the local getent accepts it, to prevent a username or
	// UID from being interpreted as an option without breaking getent variants
	// that do not support end-of-options parsing here.
	if getentDoubleDashSupported() {
		args = append(args, "--")
	}
	args = append(args, usernameOrUID)

	out, err := execGetent(ctx, args...)
	if err != nil {
		log.Printf("error calling getent for user %q: %v", usernameOrUID, err)
		return getentFallback(usernameOrUID, std, err)
	}
	u, shell, err := parseGetentUser(out)
	if err != nil {
		log.Printf("getent for user %q returned invalid output %q: %v", usernameOrUID, out, err)
		return getentFallback(usernameOrUID, std, err)
	}
	return u, shell, nil
}

func getentFallback(name string, std lookupStd, getentErr error) (*user.User, string, error) {
	u, err := std(name)
	if err == nil {
		return u, "", nil
	}
	// If getent is unavailable on this system, os/user is authoritative.
	// Otherwise only exit 2 means the requested key was not found.
	exit, _ := errors.AsType[*exec.ExitError](getentErr)
	if errors.Is(getentErr, exec.ErrNotFound) || (exit != nil && exit.ExitCode() == 2) {
		return nil, "", err
	}
	return nil, "", fmt.Errorf("getent lookup failed: %w (os/user fallback: %v)", getentErr, err)
}

func probeGetentDoubleDashSupport() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := execGetent(ctx, "passwd", "root")
	if err != nil {
		return false
	}

	outDoubleDash, err := execGetent(ctx, "passwd", "--", "root")
	if err != nil {
		return false
	}

	u, shell, err := parseGetentUser(out)
	if err != nil {
		return false
	}

	uDoubleDash, shellDoubleDash, err := parseGetentUser(outDoubleDash)
	if err != nil {
		return false
	}

	// Short-circuit if the user is obviously incorrect
	if uDoubleDash.Name != "root" || uDoubleDash.Uid != "0" || uDoubleDash.Gid != "0" {
		return false
	}

	if !reflect.DeepEqual(u, uDoubleDash) || shell != shellDoubleDash {
		return false
	}

	return true
}

func parseGetentUser(out []byte) (*user.User, string, error) {
	// output is "alice:x:1001:1001:Alice Smith,,,:/home/alice:/bin/bash"
	//
	// A single getent record is one line; embedded newlines mean getent
	// returned multiple or corrupted records. A record is exactly seven
	// colon-separated fields — the passwd format has no escaping (gecos
	// sub-fields are comma-separated), so an eighth field means a stray
	// colon shifted every later field: home would parse as a gecos
	// fragment and shell as the real home directory.
	s := strings.TrimSpace(string(out))
	if strings.ContainsRune(s, '\n') {
		return nil, "", errors.New("getent passwd output is not a single line")
	}
	f := strings.SplitN(s, ":", 10)
	if len(f) > 7 {
		return nil, "", fmt.Errorf("getent passwd output has %d fields, want 7", len(f))
	}
	for len(f) < 7 {
		f = append(f, "")
	}
	var mandatoryFields = map[int]string{0: "Username", 2: "Uid", 3: "Gid", 5: "HomeDir"}
	for k, v := range mandatoryFields {
		if f[k] == "" {
			return nil, "", fmt.Errorf("missing mandatory field %q", v)
		}
	}
	// The username and shell are used to look up and run a session; reject
	// corrupted values (control characters, invalid UTF-8, leading dashes)
	// with the same rules as getent input (see checkGetentInput).
	if !checkParsedGetentField(f[0]) {
		return nil, "", fmt.Errorf("invalid username field %q", f[0])
	}
	if !checkParsedGetentField(f[6]) {
		return nil, "", fmt.Errorf("invalid shell field %q", f[6])
	}
	return &user.User{
		Username: f[0],
		Uid:      f[2],
		Gid:      f[3],
		Name:     f[4],
		HomeDir:  f[5],
	}, f[6], nil
}

// checkParsedGetentField reports whether a parsed getent passwd field (the
// username or shell) is safe to use: no leading dash and no control or
// invalid-UTF-8 characters. It doesn't require the field to be non-empty;
// mandatory fields are checked by the caller.
func checkParsedGetentField(s string) bool {
	if strings.HasPrefix(s, "-") {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return false
		}
	}
	return true
}
