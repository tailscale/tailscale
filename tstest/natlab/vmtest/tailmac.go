// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// macosVMDir returns the base directory for macOS VM images.
func macosVMDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cache", "tailscale", "vmtest", "macos"), nil
}

// ensureTailMac locates the pre-built tailmac Host.app binary.
// Users must build it first with "make all" in tstest/tailmac/.
func (e *Env) ensureTailMac() error {
	modRoot, err := findModRoot()
	if err != nil {
		return err
	}
	e.tailmacDir = filepath.Join(modRoot, "tstest", "tailmac", "bin")
	hostApp := filepath.Join(e.tailmacDir, "Host.app", "Contents", "MacOS", "Host")
	if _, err := os.Stat(hostApp); err != nil {
		return fmt.Errorf("tailmac Host.app not found at %s; run 'make all' in tstest/tailmac/", hostApp)
	}
	return nil
}

// startTailMacVM clones the base macOS VM, configures it for this test's
// vnet, and launches it headlessly via the tailmac Host.app.
//
// The base VM is created by "go run ./tstest/build-macos-base-vm". The
// headless Host.app uses a single socket-based NIC (matching the base VM's
// config) connected directly to vnet's dgram socket.
func (e *Env) startTailMacVM(n *Node) error {
	baseID := *macosVMID
	testID := fmt.Sprintf("vmtest-%s-%d", n.name, os.Getpid())

	vmBase, err := macosVMDir()
	if err != nil {
		return err
	}
	baseDir := filepath.Join(vmBase, baseID)
	if _, err := os.Stat(baseDir); err != nil {
		return fmt.Errorf("base macOS VM %q not found at %s; create with: go run ./tstest/build-macos-base-vm", baseID, baseDir)
	}

	// Clone the base VM (APFS CoW via cp -c makes this nearly instant).
	cloneDir := filepath.Join(vmBase, testID)
	e.t.Logf("[%s] cloning macOS VM %s -> %s", n.name, baseID, testID)
	if out, err := exec.Command("cp", "-c", "-r", baseDir, cloneDir).CombinedOutput(); err != nil {
		if out2, err2 := exec.Command("cp", "-r", baseDir, cloneDir).CombinedOutput(); err2 != nil {
			return fmt.Errorf("cloning macOS VM: %v: %s (APFS clone: %v: %s)", err2, out2, err, out)
		}
	}
	e.t.Cleanup(func() {
		os.RemoveAll(cloneDir)
	})

	// Write config.json with test-specific MAC and the vnet dgram socket path.
	// The serverSocket field tells the Swift code where to connect the VM's NIC.
	mac := n.vnetNode.NICMac(0)
	cfg := struct {
		VMid         string `json:"vmID"`
		ServerSocket string `json:"serverSocket"`
		MemorySize   uint64 `json:"memorySize"`
		Mac          string `json:"mac"`
	}{
		VMid:         testID,
		ServerSocket: e.dgramSockAddr,
		MemorySize:   8 * 1024 * 1024 * 1024, // 8GB, matching base VM
		Mac:          mac.String(),
	}
	cfgData, _ := json.MarshalIndent(cfg, "", "  ")
	cfgPath := filepath.Join(cloneDir, "config.json")
	if err := os.WriteFile(cfgPath, cfgData, 0644); err != nil {
		return fmt.Errorf("writing config.json: %w", err)
	}
	e.t.Logf("[%s] macOS VM config: mac=%s, socket=%s", n.name, mac, e.dgramSockAddr)

	// Launch Host.app in headless mode. Headless mode uses a single NIC
	// connected to the vnet dgram socket.
	hostBin := filepath.Join(e.tailmacDir, "Host.app", "Contents", "MacOS", "Host")
	args := []string{"run", "--id", testID, "--headless"}

	logPath := filepath.Join(e.tempDir, n.name+"-tailmac.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("creating log file: %w", err)
	}

	cmd := exec.Command(hostBin, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		logFile.Close()
		return fmt.Errorf("open /dev/null: %w", err)
	}
	cmd.Stdin = devNull

	if err := cmd.Start(); err != nil {
		devNull.Close()
		logFile.Close()
		return fmt.Errorf("starting tailmac for %s: %w", n.name, err)
	}
	e.t.Logf("[%s] launched tailmac (pid %d), log: %s", n.name, cmd.Process.Pid, logPath)

	// The Swift code creates a client dgram socket at /tmp/qemu-dgram-<id>.sock
	clientSock := fmt.Sprintf("/tmp/qemu-dgram-%s.sock", testID)

	e.t.Cleanup(func() {
		cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			cmd.Process.Kill()
			<-done
		}
		devNull.Close()
		logFile.Close()
		os.Remove(clientSock)

		if e.t.Failed() {
			if data, err := os.ReadFile(logPath); err == nil {
				lines := strings.Split(string(data), "\n")
				start := 0
				if len(lines) > 50 {
					start = len(lines) - 50
				}
				e.t.Logf("=== last 50 lines of %s tailmac log ===", n.name)
				for _, line := range lines[start:] {
					e.t.Logf("[%s] %s", n.name, line)
				}
			}
		}
	})

	return nil
}
