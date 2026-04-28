// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func init() {
	restartTailscaled = restartTailscaledLinux
}

// restartTailscaledLinux finds the tailscaled process by walking /proc and
// sends it SIGKILL. On gokrazy, the supervisor will restart tailscaled within
// a few seconds. The PID of the process that was killed is returned.
func restartTailscaledLinux() (int, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, err := os.ReadFile("/proc/" + e.Name() + "/comm")
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) != "tailscaled" {
			continue
		}
		proc, err := os.FindProcess(pid)
		if err != nil {
			return 0, err
		}
		if err := proc.Kill(); err != nil {
			return 0, fmt.Errorf("killing tailscaled pid %d: %w", pid, err)
		}
		return pid, nil
	}
	return 0, fmt.Errorf("tailscaled process not found in /proc")
}
