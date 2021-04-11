// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"

	"tailscale.com/types/logger"
)

// isResolvconfActive indicates whether the system appears to be using resolvconf.
// If this is true, then directManager should be avoided:
// resolvconf has exclusive ownership of /etc/resolv.conf.
func isResolvconfActive() bool {
	_, err := exec.LookPath("resolvconf")
	if err != nil {
		return false
	}

	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		// Look for the word "resolvconf" until comments end.
		if len(line) > 0 && line[0] != '#' {
			return false
		}
		if bytes.Contains(line, []byte("resolvconf")) {
			return true
		}
	}
	return false
}

func newResolvconfManager(logf logger.Logf) OSConfigurator {
	_, err := exec.Command("resolvconf", "--version").CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 99 {
			// Debian resolvconf doesn't understand --version, and
			// exits with a specific error code.
			return newDebianResolvconfManager(logf)
		}
	}
	// If --version works, or we got some surprising error while
	// probing, use openresolv. It's the more common implementation,
	// so in cases where we can't figure things out, it's the least
	// likely to misbehave.
	return newOpenresolvManager()
}
