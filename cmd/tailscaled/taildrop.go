// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/types/logger"
	"tailscale.com/version/distro"
)

func configureTaildrop(logf logger.Logf, lb *ipnlocal.LocalBackend) {
	dg := distro.Get()
	switch dg {
	case distro.Synology, distro.TrueNAS, distro.QNAP, distro.Unraid:
		// See if they have a "Taildrop" share.
		// See https://github.com/tailscale/tailscale/issues/2179#issuecomment-982821319
		path, err := findTaildropDir(dg)
		if err != nil {
			logf("%s Taildrop support: %v", dg, err)
		} else {
			logf("%s Taildrop: using %v", dg, path)
			lb.SetDirectFileRoot(path)
		}
	}

}

func findTaildropDir(dg distro.Distro) (string, error) {
	const name = "Taildrop"
	switch dg {
	case distro.Synology:
		return findSynologyTaildropDir(name)
	case distro.TrueNAS:
		return findTrueNASTaildropDir(name)
	case distro.QNAP:
		return findQnapTaildropDir(name)
	case distro.Unraid:
		return findUnraidTaildropDir(name)
	}
	return "", fmt.Errorf("%s is an unsupported distro for Taildrop dir", dg)
}

// findSynologyTaildropDir looks for the first volume containing a
// "Taildrop" directory.  We'd run "synoshare --get Taildrop" command
// but on DSM7 at least, we lack permissions to run that.
func findSynologyTaildropDir(name string) (dir string, err error) {
	for i := 1; i <= 16; i++ {
		dir = fmt.Sprintf("/volume%v/%s", i, name)
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			return dir, nil
		}
	}
	return "", fmt.Errorf("shared folder %q not found", name)
}

// findTrueNASTaildropDir returns the first matching directory of
// /mnt/{name} or /mnt/*/{name}
func findTrueNASTaildropDir(name string) (dir string, err error) {
	// If we're running in a jail, a mount point could just be added at /mnt/Taildrop
	dir = fmt.Sprintf("/mnt/%s", name)
	if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
		return dir, nil
	}

	// but if running on the host, it may be something like /mnt/Primary/Taildrop
	fis, err := os.ReadDir("/mnt")
	if err != nil {
		return "", fmt.Errorf("error reading /mnt: %w", err)
	}
	for _, fi := range fis {
		dir = fmt.Sprintf("/mnt/%s/%s", fi.Name(), name)
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			return dir, nil
		}
	}
	return "", fmt.Errorf("shared folder %q not found", name)
}

// findQnapTaildropDir checks if a Shared Folder named "Taildrop" exists.
func findQnapTaildropDir(name string) (string, error) {
	dir := fmt.Sprintf("/share/%s", name)
	fi, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("shared folder %q not found", name)
	}
	if fi.IsDir() {
		return dir, nil
	}

	// share/Taildrop is usually a symlink to CACHEDEV1_DATA/Taildrop/ or some such.
	fullpath, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("symlink to shared folder %q not found", name)
	}
	if fi, err = os.Stat(fullpath); err == nil && fi.IsDir() {
		return dir, nil // return the symlink, how QNAP set it up
	}
	return "", fmt.Errorf("shared folder %q not found", name)
}

// findUnraidTaildropDir looks for a directory linked at
// /var/lib/tailscale/Taildrop. This is a symlink to the
// path specified by the user in the Unraid Web UI
func findUnraidTaildropDir(name string) (string, error) {
	dir := fmt.Sprintf("/var/lib/tailscale/%s", name)
	_, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("symlink %q not found", name)
	}

	fullpath, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("symlink %q to shared folder not valid", name)
	}

	fi, err := os.Stat(fullpath)
	if err == nil && fi.IsDir() {
		return dir, nil // return the symlink
	}
	return "", fmt.Errorf("shared folder %q not found", name)
}
