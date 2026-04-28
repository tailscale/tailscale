// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const tartImage = "ghcr.io/cirruslabs/macos-tahoe-base:latest"

// tartConfig is the subset of Tart's config.json we need.
type tartConfig struct {
	HardwareModel string `json:"hardwareModel"` // base64
	ECID          string `json:"ecid"`          // base64
}

// ensureTartImage checks that the Tart base image is available, pulling it
// if necessary. Returns the path to a directory containing disk.img,
// nvram.bin, and config.json.
func ensureTartImage(t testing.TB) string {
	if _, err := exec.LookPath("tart"); err != nil {
		t.Skip("tart not installed; skipping macOS VM test")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}

	// Check OCI cache first (from a previous "tart pull").
	ociDir := filepath.Join(home, ".tart", "cache", "OCIs",
		"ghcr.io", "cirruslabs", "macos-tahoe-base", "latest")
	if _, err := os.Stat(filepath.Join(ociDir, "disk.img")); err == nil {
		return ociDir
	}

	t.Logf("pulling Tart image %s ...", tartImage)
	cmd := exec.Command("tart", "pull", tartImage)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("tart pull: %v", err)
	}

	// After pull, the OCI cache should have it.
	if _, err := os.Stat(filepath.Join(ociDir, "disk.img")); err == nil {
		return ociDir
	}
	t.Fatalf("tart pull succeeded but image not found at %s", ociDir)
	return ""
}

// ensureTailMac locates the pre-built tailmac Host.app binary.
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

// cloneTartToTailmac creates a tailmac-compatible VM directory from a Tart
// base image. It uses APFS CoW clones for the disk and NVRAM, and extracts
// the hardware identity from Tart's config.json.
func cloneTartToTailmac(tartDir, cloneDir, testID, mac, dgramSock string) error {
	if err := os.MkdirAll(cloneDir, 0755); err != nil {
		return err
	}

	// Read Tart's config.json for hardware identity.
	cfgData, err := os.ReadFile(filepath.Join(tartDir, "config.json"))
	if err != nil {
		return fmt.Errorf("reading tart config: %w", err)
	}
	var tc tartConfig
	if err := json.Unmarshal(cfgData, &tc); err != nil {
		return fmt.Errorf("parsing tart config: %w", err)
	}

	// Decode and write HardwareModel.
	hwModel, err := base64.StdEncoding.DecodeString(tc.HardwareModel)
	if err != nil {
		return fmt.Errorf("decoding hardwareModel: %w", err)
	}
	if err := os.WriteFile(filepath.Join(cloneDir, "HardwareModel"), hwModel, 0644); err != nil {
		return err
	}

	// Decode and write MachineIdentifier (ECID).
	ecid, err := base64.StdEncoding.DecodeString(tc.ECID)
	if err != nil {
		return fmt.Errorf("decoding ecid: %w", err)
	}
	if err := os.WriteFile(filepath.Join(cloneDir, "MachineIdentifier"), ecid, 0644); err != nil {
		return err
	}

	// APFS clone the disk image (nearly instant, copy-on-write).
	if out, err := exec.Command("cp", "-c", filepath.Join(tartDir, "disk.img"), filepath.Join(cloneDir, "Disk.img")).CombinedOutput(); err != nil {
		// Fallback to regular copy.
		if out2, err2 := exec.Command("cp", filepath.Join(tartDir, "disk.img"), filepath.Join(cloneDir, "Disk.img")).CombinedOutput(); err2 != nil {
			return fmt.Errorf("copying disk: %v: %s (APFS clone: %v: %s)", err2, out2, err, out)
		}
	}

	// APFS clone the NVRAM.
	if out, err := exec.Command("cp", "-c", filepath.Join(tartDir, "nvram.bin"), filepath.Join(cloneDir, "AuxiliaryStorage")).CombinedOutput(); err != nil {
		if out2, err2 := exec.Command("cp", filepath.Join(tartDir, "nvram.bin"), filepath.Join(cloneDir, "AuxiliaryStorage")).CombinedOutput(); err2 != nil {
			return fmt.Errorf("copying nvram: %v: %s (APFS clone: %v: %s)", err2, out2, err, out)
		}
	}

	// Write tailmac config.json.
	tmCfg := struct {
		VMid         string `json:"vmID"`
		ServerSocket string `json:"serverSocket"`
		MemorySize   uint64 `json:"memorySize"`
		Mac          string `json:"mac"`
	}{
		VMid:         testID,
		ServerSocket: dgramSock,
		MemorySize:   8 * 1024 * 1024 * 1024,
		Mac:          mac,
	}
	tmData, _ := json.MarshalIndent(tmCfg, "", "  ")
	return os.WriteFile(filepath.Join(cloneDir, "config.json"), tmData, 0644)
}

// startTailMacVM clones a Tart base image and launches it via tailmac
// Host.app in headless mode, connected to vnet's dgram socket.
func (e *Env) startTailMacVM(n *Node) error {
	tartDir := ensureTartImage(e.t)

	if err := e.ensureTailMac(); err != nil {
		return err
	}

	testID := fmt.Sprintf("vmtest-%s-%d", n.name, os.Getpid())

	// Host.app expects VM files under ~/.cache/tailscale/vmtest/macos/<id>/
	// (hardcoded in Config.swift's vmBundleURL).
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("UserHomeDir: %w", err)
	}
	vmBase := filepath.Join(home, ".cache", "tailscale", "vmtest", "macos")
	os.MkdirAll(vmBase, 0755)
	cloneDir := filepath.Join(vmBase, testID)

	mac := n.vnetNode.NICMac(0)
	e.t.Logf("[%s] cloning Tart image -> %s (mac=%s)", n.name, testID, mac)
	if err := cloneTartToTailmac(tartDir, cloneDir, testID, mac.String(), e.dgramSockAddr); err != nil {
		return fmt.Errorf("cloning tart VM: %w", err)
	}
	e.t.Cleanup(func() { os.RemoveAll(cloneDir) })

	hostBin := filepath.Join(e.tailmacDir, "Host.app", "Contents", "MacOS", "Host")
	args := []string{
		"run", "--id", testID, "--headless",
	}

	wantScreenshots := *vmtestWeb != ""
	if wantScreenshots {
		args = append(args, "--screenshot-port", "0")
	}

	logPath := filepath.Join(e.tempDir, n.name+"-tailmac.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("creating log file: %w", err)
	}

	cmd := exec.Command(hostBin, args...)
	cmd.Env = append(os.Environ(), "NSUnbufferedIO=YES")

	// If screenshots are enabled, we need to parse stdout for the
	// SCREENSHOT_PORT=<port> line, while also logging everything to file.
	var stdoutPipe io.ReadCloser
	if wantScreenshots {
		stdoutPipe, err = cmd.StdoutPipe()
		if err != nil {
			logFile.Close()
			return fmt.Errorf("stdout pipe: %w", err)
		}
		cmd.Stderr = logFile
	} else {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}
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

	// Parse screenshot port from stdout and start polling goroutine.
	if wantScreenshots {
		screenshotPortCh := make(chan int, 1)
		go func() {
			scanner := bufio.NewScanner(stdoutPipe)
			for scanner.Scan() {
				line := scanner.Text()
				fmt.Fprintln(logFile, line) // tee to log file
				if port := 0; strings.HasPrefix(line, "SCREENSHOT_PORT=") {
					fmt.Sscanf(line, "SCREENSHOT_PORT=%d", &port)
					if port > 0 {
						screenshotPortCh <- port
					}
				}
			}
		}()
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			select {
			case port := <-screenshotPortCh:
				e.t.Logf("[%s] screenshot server on port %d", n.name, port)
				e.setNodeScreenshotPort(n.name, port)
				e.tailScreenshots(n.name, port)
			case <-ctx.Done():
				e.t.Logf("[%s] screenshot port not received", n.name)
			}
		}()
	}

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

// tailScreenshots polls the Host.app screenshot HTTP server every 2 seconds
// and publishes each screenshot as a base64 data URI to the web UI.
func (e *Env) tailScreenshots(name string, port int) {
	url := fmt.Sprintf("http://127.0.0.1:%d/screenshot", port)
	client := &http.Client{Timeout: 5 * time.Second}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || len(data) == 0 {
			continue
		}
		b64 := base64.StdEncoding.EncodeToString(data)
		dataURI := "data:image/jpeg;base64," + b64
		e.setNodeScreenshot(name, dataURI)
		e.eventBus.Publish(VMEvent{
			NodeName: name,
			Type:     EventScreenshot,
			Message:  b64,
		})
	}
}
