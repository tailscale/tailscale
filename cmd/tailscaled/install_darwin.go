// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
)

func init() {
	installSystemDaemon = installSystemDaemonDarwin
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
const service = "system/com.tailscale.tailscaled"

func installSystemDaemonDarwin() (err error) {
	defer func() {
		if err != nil && os.Getuid() != 0 {
			err = fmt.Errorf("%w; try running tailscaled with sudo", err)
		}
	}()

	// Copy ourselves to /usr/local/bin/tailscaled.
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to find our own executable path: %w", err)
	}
	tmpBin := targetBin + ".tmp"
	f, err := os.Create(tmpBin)
	if err != nil {
		return err
	}
	self, err := os.Open(exe)
	if err != nil {
		f.Close()
		return err
	}
	_, err = io.Copy(f, self)
	self.Close()
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
	if err := os.Rename(tmpBin, targetBin); err != nil {
		return err
	}

	// Two best effort commands to stop a previous run.
	exec.Command("launchctl", "stop", "system/com.tailscale.tailscaled").Run()
	exec.Command("launchctl", "unload", sysPlist).Run()

	if err := ioutil.WriteFile(sysPlist, []byte(darwinLaunchdPlist), 0700); err != nil {
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
