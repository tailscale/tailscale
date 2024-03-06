// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin

package tailfs

import (
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
)

// DefaultAutomountPath returns the default automount path. If blank, that
// means TailFS is disabled on this platform.
func DefaultAutomountPath() string {
	return "/Volumes/tailscale"
}

func MountShares(location string, username string) {
	u, err := user.Lookup(username)
	if err != nil {
		log.Printf("warning: error looking up user %q, won't automount shares: %s", username, err)
		return
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		log.Printf("warning: failed to parse uid %q, won't automount shares: %s", u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		log.Printf("warning: failed to parse gid %q, won't automount shares: %s", u.Gid, err)
	}

	location = filepath.Clean(location)
	err = os.MkdirAll(location, 0700)
	if err != nil {
		log.Printf("warning: can't make automount location %q: %s", location, err)
		return
	}

	err = os.Chown(location, uid, gid)
	if err != nil {
		log.Printf("warning: failed to chown automount location, won't automount shares: %s", err)
	}

	out, err := exec.Command("sudo", "-u", username, "mount", "-t", "webdav", "http://100.100.100.100:8080", location).CombinedOutput()
	if err != nil {
		log.Printf("warning: can't automount shares at %q: %s", location, out)
	}
}

func UnmountShares(location string) {
	location = filepath.Clean(location)
	out, err := exec.Command("diskutil", "umount", location).CombinedOutput()
	if err != nil {
		log.Printf("warning: can't unmount shares from %q: %s", location, out)
	}
}
