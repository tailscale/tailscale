// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build cgo || !darwin

// Package systray provides a minimal Tailscale systray application.
package systray

import (
	"bufio"
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"tailscale.com/client/freedesktop"
)

//go:embed tailscale-systray.service
var embedSystemd string

//go:embed tailscale-systray.desktop
var embedFreedesktop string

//go:embed tailscale.svg
var embedLogoSvg string

//go:embed tailscale.png
var embedLogoPng string

func InstallStartupScript(initSystem string) error {
	switch initSystem {
	case "systemd":
		return installSystemd()
	case "freedesktop":
		return installFreedesktop()
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
		return fmt.Errorf("failed creating systemd user dir: %w", err)
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

func installFreedesktop() error {
	tmpDir, err := os.MkdirTemp("", "tailscale-systray")
	if err != nil {
		return fmt.Errorf("unable to make tmpDir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Install icon, and use it if it works, and if not change to some generic
	// network/vpn icon.
	iconName := "tailscale"
	if err := installIcon(tmpDir); err != nil {
		iconName = "network-transmit"
		fmt.Printf("unable to install icon, continuing without: %s\n", err.Error())
	}

	// Create desktop file in a tmp dir
	desktopTmpPath := filepath.Join(tmpDir, "tailscale-systray.desktop")
	if err := os.WriteFile(desktopTmpPath, []byte(embedFreedesktop),
		0o0755); err != nil {
		return fmt.Errorf("unable to create desktop file: %w", err)
	}

	// Ensure autostart dir exists and install the desktop file
	configDir, err := os.UserConfigDir()
	if err != nil {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("unable to locate user home: %w", err)
		}
		configDir = filepath.Join(homeDir, ".config")
	}

	autostartDir := filepath.Join(configDir, "autostart")
	if err := os.MkdirAll(autostartDir, 0o644); err != nil {
		return fmt.Errorf("failed creating freedesktop autostart dir: %w", err)
	}

	desktopCmd := exec.Command("desktop-file-install", "--dir", autostartDir,
		desktopTmpPath)
	if output, err := desktopCmd.Output(); err != nil {
		return fmt.Errorf("unable to install desktop file: %w - %s", err, output)
	}

	// Find the path to tailscale, just in case it's not where the example file
	// has it placed, and replace that before writing the file.
	tailscaleBin, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to find tailscale binary %w", err)
	}
	tailscaleBin = freedesktop.Quote(tailscaleBin)

	// Make possible changes to the desktop file
	runEdit := func(args ...string) error {
		cmd := exec.Command("desktop-file-edit", args...)
		out, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("cmd: %s: %w\n%s", cmd.String(), err, out)
		}
		return nil
	}

	edits := [][]string{
		{"--set-key=Exec", "--set-value=" + tailscaleBin + " systray"},
		{"--set-key=TryExec", "--set-value=" + tailscaleBin},
		{"--set-icon=" + iconName},
	}

	var errs []error
	desktopFile := filepath.Join(autostartDir, "tailscale-systray.desktop")
	for _, args := range edits {
		args = append(args, desktopFile)
		if err := runEdit(args...); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf(
			"failed changing autostart file, try rebooting: %w", errors.Join(errs...))
	}

	fmt.Printf("Successfully installed freedesktop autostart service to: %s\n", desktopFile)
	fmt.Println("The service will run upon logging in.")

	return nil
}

// installIcon installs an icon using the freedesktop tools. SVG support
// is still on its way for some distros, notably missing on Ubuntu 25.10 as of
// 2026-02-19. Try to install both icons and let the DE decide from what is
// available.
// Reference: https://gitlab.freedesktop.org/xdg/xdg-utils/-/merge_requests/116
func installIcon(tmpDir string) error {
	svgPath := filepath.Join(tmpDir, "tailscale.svg")
	if err := os.WriteFile(svgPath, []byte(embedLogoSvg), 0o0644); err != nil {
		return fmt.Errorf("unable to create svg: %w", err)
	}

	pngPath := filepath.Join(tmpDir, "tailscale.png")
	if err := os.WriteFile(pngPath, []byte(embedLogoPng), 0o0644); err != nil {
		return fmt.Errorf("unable to create png: %w", err)
	}

	var errs []error
	installed := false
	svgCmd := exec.Command("xdg-icon-resource", "install", "--size", "scalable",
		"--novendor", svgPath, "tailscale")
	if output, err := svgCmd.Output(); err != nil {
		errs = append(errs, fmt.Errorf("unable to install svg: %s - %s", err, output))
	} else {
		installed = true
	}
	pngCmd := exec.Command("xdg-icon-resource", "install", "--size", "512",
		"--novendor", pngPath, "tailscale")
	if output, err := pngCmd.Output(); err != nil {
		errs = append(errs, fmt.Errorf("unable to install png: %s - %s", err, output))
	} else {
		installed = true
	}

	if !installed {
		return errors.Join(errs...)
	}
	return nil
}
