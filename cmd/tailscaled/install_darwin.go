// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.19
// +build go1.19

package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
)

func init() {
	installSystemDaemon = installSystemDaemonDarwin
	uninstallSystemDaemon = uninstallSystemDaemonDarwin
}

// darwinLaunchdPlist is the launchd.plist that's written to
// /Library/LaunchDaemons/com.tailscale.tailscaled.plist or (in the
// future) a user-specific location.
//
// See man launchd.plist.
const darwinLaunchdPlist = `
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>

  <key>Label</key>
  <string>com.tailscale.tailscaled</string>

  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/tailscaled</string>
  </array>

  <key>RunAtLoad</key>
  <true/>

</dict>
</plist>
`

const sysPlist = "/Library/LaunchDaemons/com.tailscale.tailscaled.plist"
const targetBin = "/usr/local/bin/tailscaled"
const service = "com.tailscale.tailscaled"

func uninstallSystemDaemonDarwin(args []string) (ret error) {
	if len(args) > 0 {
		return errors.New("uninstall subcommand takes no arguments")
	}

	plist, err := exec.Command("launchctl", "list", "com.tailscale.tailscaled").Output()
	_ = plist // parse it? https://github.com/DHowett/go-plist if we need something.
	running := err == nil

	if running {
		out, err := exec.Command("launchctl", "stop", "com.tailscale.tailscaled").CombinedOutput()
		if err != nil {
			fmt.Printf("launchctl stop com.tailscale.tailscaled: %v, %s\n", err, out)
			ret = err
		}
		out, err = exec.Command("launchctl", "unload", sysPlist).CombinedOutput()
		if err != nil {
			fmt.Printf("launchctl unload %s: %v, %s\n", sysPlist, err, out)
			if ret == nil {
				ret = err
			}
		}
	}

	if err := os.Remove(sysPlist); err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		if ret == nil {
			ret = err
		}
	}

	// Do not delete targetBin if it's a symlink, which happens if it was installed via
	// Homebrew.
	if isSymlink(targetBin) {
		return ret
	}

	if err := os.Remove(targetBin); err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		if ret == nil {
			ret = err
		}
	}
	return ret
}

func installSystemDaemonDarwin(args []string) (err error) {
	if len(args) > 0 {
		return errors.New("install subcommand takes no arguments")
	}
	defer func() {
		if err != nil && os.Getuid() != 0 {
			err = fmt.Errorf("%w; try running tailscaled with sudo", err)
		}
	}()

	// Best effort:
	uninstallSystemDaemonDarwin(nil)

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to find our own executable path: %w", err)
	}

	same, err := sameFile(exe, targetBin)
	if err != nil {
		return err
	}

	// Do not overwrite targetBin with the binary file if it it's already
	// pointing to it. This is primarily to handle Homebrew that writes
	// /usr/local/bin/tailscaled is a symlink to the actual binary.
	if !same {
		if err := copyBinary(exe, targetBin); err != nil {
			return err
		}
	}
	if err := os.WriteFile(sysPlist, []byte(darwinLaunchdPlist), 0700); err != nil {
		return err
	}

	if out, err := exec.Command("launchctl", "load", sysPlist).CombinedOutput(); err != nil {
		return fmt.Errorf("error running launchctl load %s: %v, %s", sysPlist, err, out)
	}

	if out, err := exec.Command("launchctl", "start", service).CombinedOutput(); err != nil {
		return fmt.Errorf("error running launchctl start %s: %v, %s", service, err, out)
	}

	return nil
}

// copyBinary copies binary file `src` into `dst`.
func copyBinary(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	tmpBin := dst + ".tmp"
	f, err := os.Create(tmpBin)
	if err != nil {
		return err
	}
	srcf, err := os.Open(src)
	if err != nil {
		f.Close()
		return err
	}
	_, err = io.Copy(f, srcf)
	srcf.Close()
	if err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpBin, 0755); err != nil {
		return err
	}
	if err := os.Rename(tmpBin, dst); err != nil {
		return err
	}

	return nil
}

func isSymlink(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && (fi.Mode()&os.ModeSymlink == os.ModeSymlink)
}

// sameFile returns true if both file paths exist and resolve to the same file.
func sameFile(path1, path2 string) (bool, error) {
	dst1, err := filepath.EvalSymlinks(path1)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("EvalSymlinks(%s): %w", path1, err)
	}
	dst2, err := filepath.EvalSymlinks(path2)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("EvalSymlinks(%s): %w", path2, err)
	}
	return dst1 == dst2, nil
}
