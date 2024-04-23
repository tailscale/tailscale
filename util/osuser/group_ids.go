// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package osuser

import (
	"context"
	"fmt"
	"os/exec"
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
	if runtime.GOOS != "linux" {
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "id", "-Gz", usernameOrUID)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running 'id' command: %w", err)
	}
	return parseGroupIds(out), nil
}

func parseGroupIds(cmdOutput []byte) []string {
	return strings.Split(strings.Trim(string(cmdOutput), "\n\x00"), "\x00")
}
