// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package osuser

import (
	"context"
	"errors"
	"fmt"
	"os/user"
	"runtime"
	"strings"
	"time"

	"tailscale.com/version/distro"
)

// GetGroupIds returns the list of group IDs that the user is a member of, or
// an error. It will first try to use the 'id' command to get the group IDs,
// and if that fails, it will fall back to the user.GroupIds method.
func GetGroupIds(user *user.User) ([]string, error) {
	if runtime.GOOS == "plan9" {
		return nil, nil
	}

	if runtime.GOOS != "linux" && runtime.GOOS != "freebsd" {
		return user.GroupIds()
	}

	if distro.Get() == distro.Gokrazy {
		// Gokrazy is a single-user appliance with ~no userspace.
		// There aren't users to look up (no /etc/passwd, etc)
		// so rather than fail below, just hardcode root.
		// TODO(bradfitz): fix os/user upstream instead?
		return []string{"0"}, nil
	}

	if ids, err := getGroupIdsWithId(user.Username); err == nil {
		return ids, nil
	}
	return user.GroupIds()
}

func getGroupIdsWithId(usernameOrUID string) ([]string, error) {
	// Do some basic validation before passing this string to the "id"
	// command, with the same rules as getent (see checkGetentInput), so a
	// crafted username like "-u" can't be interpreted as an option.
	if !checkGetentInput(usernameOrUID) {
		return nil, errors.New("invalid username or UID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	idArgs := []string{"-Gz", usernameOrUID}
	if runtime.GOOS == "freebsd" {
		idArgs = []string{"-G", usernameOrUID}
	}
	out, err := execId(ctx, idArgs...)
	if err != nil {
		return nil, fmt.Errorf("running 'id' command: %w", err)
	}

	return parseGroupIds(out), nil
}

func parseGroupIds(cmdOutput []byte) []string {
	s := strings.TrimSpace(string(cmdOutput))
	// Parse NUL-delimited output.
	if strings.ContainsRune(s, '\x00') {
		return strings.Split(strings.Trim(s, "\x00"), "\x00")
	}
	// Parse whitespace-delimited output.
	return strings.Fields(s)
}
