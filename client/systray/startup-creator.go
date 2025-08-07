// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build cgo || !darwin

// Package systray provides a minimal Tailscale systray application.
package systray

import (
	"bufio"
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed tailscale-systray.service
var embedSystemd string

func InstallStartupScript(initSystem string) error {
	switch initSystem {
	case "systemd":
		return installSystemd()
	default:
		return fmt.Errorf("unsupported init system '%s'", initSystem)
	}
}

func installSystemd() error {
	// Find the path to tailscale, just in case it's not where the example file
	// has it placed, and replace that before writing the file.
	tailscaleBin, err := exec.LookPath("tailscale")
	if err != nil {
		return fmt.Errorf("failed to find tailscale binary %w", err)
	}

	var output bytes.Buffer
	scanner := bufio.NewScanner(strings.NewReader(embedSystemd))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "ExecStart=") {
			line = fmt.Sprintf("ExecStart=%s systray", tailscaleBin)
		}
		output.WriteString(line + "\n")
	}

	configDir, err := os.UserConfigDir()
	if err != nil {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("unable to locate user home: %w", err)
		}
		configDir = filepath.Join(homeDir, ".config")
	}

	systemdDir := filepath.Join(configDir, "systemd", "user")
	if err := os.MkdirAll(systemdDir, 0o755); err != nil {
		return fmt.Errorf("failed creating systemd uuser dir: %w", err)
	}

	serviceFile := filepath.Join(systemdDir, "tailscale-systray.service")

	if err := os.WriteFile(serviceFile, output.Bytes(), 0o755); err != nil {
		return fmt.Errorf("failed writing systemd user service: %w", err)
	}

	fmt.Printf("Successfully installed systemd service to: %s\n", serviceFile)
	fmt.Println("To enable and start the service, run:")
	fmt.Println("  systemctl --user daemon-reload")
	fmt.Println("  systemctl --user enable --now tailscale-systray")

	return nil
}
