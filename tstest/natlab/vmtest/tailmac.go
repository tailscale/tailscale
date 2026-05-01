// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// macPlatform boots macOS VMs via Tart base images and tailmac Host.app.
type macPlatform struct{}

func (macPlatform) planSteps(e *Env, n *Node) {
	e.Step("Prepare macOS Tart image")
	e.Step("Launch macOS VM: " + n.name)
}

func (macPlatform) boot(ctx context.Context, e *Env, n *Node) error {
	imgStep := e.Step("Prepare macOS Tart image")
	e.macosSnapshotOnce.Do(func() {
		imgStep.Begin()
		e.macosSnapshot = ensureSnapshot(e.t)
		imgStep.End(nil)
	})

	e.ensureDgramSocket()

	vmStep := e.Step("Launch macOS VM: " + n.name)
	vmStep.Begin()
	if err := e.startTailMacVM(n); err != nil {
		vmStep.End(err)
		return err
	}
	vmStep.End(nil)
	return nil
}

const tartImage = "ghcr.io/cirruslabs/macos-tahoe-base:latest"

// macOSSnapshotCodeVersion is bumped when the snapshot preparation logic
// changes in a way that invalidates old snapshots. Old snapshots with a
// different version are cleaned up automatically.
const macOSSnapshotCodeVersion = 5

// tartConfig is the subset of Tart's config.json we need.
type tartConfig struct {
	HardwareModel string `json:"hardwareModel"` // base64
	ECID          string `json:"ecid"`          // base64
}

// tartManifest is the subset of Tart's OCI manifest.json we need.
type tartManifest struct {
	Config struct {
		Digest string `json:"digest"` // e.g. "sha256:3a6cb4eb6201..."
	} `json:"config"`
}

// ensureTartImage checks that the Tart base image is available, pulling it
// if necessary. Returns the path to the OCI cache directory containing
// disk.img, nvram.bin, config.json, and manifest.json.
func ensureTartImage(t testing.TB) string {
	if _, err := exec.LookPath("tart"); err != nil {
		t.Skip("tart not installed; skipping macOS VM test")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}

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

	if _, err := os.Stat(filepath.Join(ociDir, "disk.img")); err == nil {
		return ociDir
	}
	t.Fatalf("tart pull succeeded but image not found at %s", ociDir)
	return ""
}

// snapshotCacheKey computes a cache key for the macOS VM snapshot.
// The key combines the image name, the first 12 hex chars of the Tart
// config digest (changes when the upstream image is updated), and the
// snapshot code version (changes when our prep logic changes).
func snapshotCacheKey(tartDir string) (string, error) {
	manifestPath := filepath.Join(tartDir, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", fmt.Errorf("reading manifest: %w", err)
	}
	var m tartManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return "", fmt.Errorf("parsing manifest: %w", err)
	}
	digest := m.Config.Digest
	// Strip "sha256:" prefix and take first 12 hex chars.
	digest = strings.TrimPrefix(digest, "sha256:")
	if len(digest) > 12 {
		digest = digest[:12]
	}
	return fmt.Sprintf("snap-tahoe-%s-v%d", digest, macOSSnapshotCodeVersion), nil
}

// macosVMBaseDir returns ~/.cache/tailscale/vmtest/macos/, the directory
// where Host.app expects to find VM directories by ID.
func macosVMBaseDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cache", "tailscale", "vmtest", "macos"), nil
}

// cleanOldSnapshots removes any snapshot directories for the given image
// prefix (e.g. "snap-tahoe") that don't match the current cache key.
func cleanOldSnapshots(t testing.TB, imagePrefix, currentKey string) {
	base, err := macosVMBaseDir()
	if err != nil {
		return
	}
	matches, _ := filepath.Glob(filepath.Join(base, imagePrefix+"-*"))
	currentPath := filepath.Join(base, currentKey)
	for _, m := range matches {
		if m != currentPath {
			t.Logf("removing stale snapshot: %s", filepath.Base(m))
			os.RemoveAll(m)
		}
	}
}

// ensureSnapshot returns the path to a cached macOS VM snapshot, creating
// one if necessary. The snapshot contains a fully booted VM with
// SaveFile.vzvmsave ready for fast restore.
func ensureSnapshot(t testing.TB) string {
	tartDir := ensureTartImage(t)

	key, err := snapshotCacheKey(tartDir)
	if err != nil {
		t.Fatalf("snapshot cache key: %v", err)
	}

	base, err := macosVMBaseDir()
	if err != nil {
		t.Fatalf("macOS VM base dir: %v", err)
	}
	os.MkdirAll(base, 0755)

	snapDir := filepath.Join(base, key)
	saveFile := filepath.Join(snapDir, "SaveFile.vzvmsave")
	if _, err := os.Stat(saveFile); err == nil {
		t.Logf("using cached macOS snapshot: %s", key)
		return snapDir
	}

	// Clean up old snapshots for this image.
	cleanOldSnapshots(t, "snap-tahoe", key)

	t.Logf("preparing macOS snapshot: %s (this takes ~30s on first run)", key)
	if err := prepareSnapshot(t, tartDir, snapDir); err != nil {
		os.RemoveAll(snapDir)
		t.Fatalf("preparing snapshot: %v", err)
	}
	return snapDir
}

// prepareSnapshot creates a new macOS VM snapshot by booting the Tart base
// image with a NAT NIC, waiting for SSH, and saving VM state.
func prepareSnapshot(t testing.TB, tartDir, snapDir string) error {
	// The vmID must match the directory name under macosVMBaseDir
	// because Host.app looks up VM files at <base>/<vmID>/.
	snapID := filepath.Base(snapDir)

	if err := cloneTartToTailmac(tartDir, snapDir, snapID, "52:cc:cc:cc:ce:01", "/dev/null"); err != nil {
		return fmt.Errorf("cloning tart: %w", err)
	}

	modRoot, err := findModRoot()
	if err != nil {
		return err
	}
	tailmacDir := filepath.Join(modRoot, "tstest", "tailmac", "bin")
	hostBin := filepath.Join(tailmacDir, "Host.app", "Contents", "MacOS", "Host")
	if _, err := os.Stat(hostBin); err != nil {
		return fmt.Errorf("Host.app not found at %s; run 'make all' in tstest/tailmac/", hostBin)
	}

	// Host.app reads VM files from ~/.cache/tailscale/vmtest/macos/<id>/.
	// Our snapDir is already under that tree, and the config.json vmID matches.
	cmd := exec.Command(hostBin, "run", "--id", snapID, "--headless", "--nat-nic")
	cmd.Env = append(os.Environ(), "NSUnbufferedIO=YES")

	logPath := snapDir + ".prep.log"
	logFile, err := os.Create(logPath)
	if err != nil {
		return err
	}
	defer logFile.Close()
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	devNull, _ := os.Open(os.DevNull)
	cmd.Stdin = devNull
	defer devNull.Close()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting Host.app: %w", err)
	}
	t.Logf("snapshot prep: launched Host.app (pid %d)", cmd.Process.Pid)

	// Wait for SSH to become available via the NAT NIC.
	// The VM gets an IP from macOS's vmnet DHCP (typically 192.168.64.x).
	ip, err := waitForVMIP(t, "52:cc:cc:cc:ce:01", 60*time.Second)
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return fmt.Errorf("waiting for VM IP: %w", err)
	}
	t.Logf("snapshot prep: VM IP is %s, waiting for SSH...", ip)

	sc, err := waitForSSH(ip, 60*time.Second)
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return fmt.Errorf("waiting for SSH: %w", err)
	}
	t.Logf("snapshot prep: SSH connected")

	// Compile and install TTA in the macOS VM.
	t.Logf("snapshot prep: installing TTA...")
	if err := installTTA(t, sc); err != nil {
		sc.Close()
		cmd.Process.Kill()
		cmd.Wait()
		return fmt.Errorf("installing TTA: %w", err)
	}
	sc.Close()

	// Save VM state by sending SIGINT.
	t.Logf("snapshot prep: saving VM state...")
	cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			// Host.app exits 0 after saving state, non-zero is unexpected.
			t.Logf("snapshot prep: Host.app exited with: %v", err)
		}
	case <-time.After(60 * time.Second):
		cmd.Process.Kill()
		<-done
		return fmt.Errorf("Host.app did not exit after SIGINT")
	}

	// Verify the save file was created.
	saveFile := filepath.Join(snapDir, "SaveFile.vzvmsave")
	if _, err := os.Stat(saveFile); err != nil {
		return fmt.Errorf("SaveFile.vzvmsave not found after prep")
	}
	t.Logf("snapshot prep: done, saved to %s", filepath.Base(snapDir))
	os.Remove(logPath)
	return nil
}

// installTTA compiles TTA for darwin/arm64 and installs it in the macOS VM
// as a LaunchDaemon via SSH/SCP.
func installTTA(t testing.TB, sc *ssh.Client) error {
	modRoot, err := findModRoot()
	if err != nil {
		return err
	}

	// Compile TTA for the macOS VM.
	tmpDir := t.TempDir()
	ttaBin := filepath.Join(tmpDir, "tta")
	t.Logf("snapshot prep: compiling TTA for darwin/arm64...")
	buildCmd := exec.Command("go", "build", "-o", ttaBin, "./cmd/tta")
	buildCmd.Dir = modRoot
	buildCmd.Env = append(os.Environ(), "GOOS=darwin", "GOARCH=arm64", "CGO_ENABLED=0")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("compiling TTA: %v\n%s", err, out)
	}

	// Read the binary.
	ttaData, err := os.ReadFile(ttaBin)
	if err != nil {
		return fmt.Errorf("reading TTA binary: %w", err)
	}
	t.Logf("snapshot prep: TTA binary is %d bytes", len(ttaData))

	// SCP the TTA binary to the VM via a temp file (admin user can't write /usr/local/bin directly).
	if err := scpFile(sc, ttaData, "/tmp/tta", 0755); err != nil {
		return fmt.Errorf("uploading TTA: %w", err)
	}
	if err := runSSHCmd(sc, "echo admin | sudo -S mv /tmp/tta /usr/local/bin/tta"); err != nil {
		return fmt.Errorf("moving TTA to /usr/local/bin: %w", err)
	}

	// Install the LaunchDaemon plist.
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.tailscale.tta</string>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/local/bin/tta</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>/tmp/tta.log</string>
	<key>StandardErrorPath</key>
	<string>/tmp/tta.log</string>
</dict>
</plist>
`
	if err := scpFile(sc, []byte(plist), "/tmp/com.tailscale.tta.plist", 0644); err != nil {
		return fmt.Errorf("uploading plist: %w", err)
	}
	if err := runSSHCmd(sc, "echo admin | sudo -S mv /tmp/com.tailscale.tta.plist /Library/LaunchDaemons/ && echo admin | sudo -S chown root:wheel /Library/LaunchDaemons/com.tailscale.tta.plist"); err != nil {
		return fmt.Errorf("installing plist: %w", err)
	}

	// Load the LaunchDaemon.
	if err := runSSHCmd(sc, "echo admin | sudo -S launchctl load /Library/LaunchDaemons/com.tailscale.tta.plist"); err != nil {
		return fmt.Errorf("loading LaunchDaemon: %w", err)
	}

	// Wait for TTA to start.
	for range 20 {
		if err := runSSHCmd(sc, "pgrep -x tta"); err == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err := runSSHCmd(sc, "pgrep -x tta"); err != nil {
		return fmt.Errorf("TTA not running after install: %w", err)
	}
	t.Logf("snapshot prep: TTA installed and running")
	return nil
}

// scpFile uploads data to a remote path via SSH/SCP.
func scpFile(sc *ssh.Client, data []byte, remotePath string, mode os.FileMode) error {
	sess, err := sc.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	// Use a simple shell command to write the file.
	cmd := fmt.Sprintf("cat > %s && chmod %o %s", remotePath, mode, remotePath)
	sess.Stdin = bytes.NewReader(data)
	out, err := sess.CombinedOutput(cmd)
	if err != nil {
		return fmt.Errorf("%s: %v: %s", cmd, err, out)
	}
	return nil
}

// runSSHCmd runs a command on the SSH client and returns an error if it fails.
func runSSHCmd(sc *ssh.Client, cmd string) error {
	sess, err := sc.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(cmd)
	if err != nil {
		return fmt.Errorf("%s: %v: %s", cmd, err, out)
	}
	return nil
}

// waitForVMIP polls /var/db/dhcpd_leases for a DHCP lease matching the
// given MAC address (from macOS's vmnet NAT). Returns the IP.
func waitForVMIP(t testing.TB, mac string, timeout time.Duration) (string, error) {
	// Normalize MAC format: vmnet leases use "1,xx:xx:xx:xx:xx:xx" format
	// with leading zeros stripped from each octet (e.g. "1,52:cc:cc:cc:ce:1"
	// instead of "1,52:cc:cc:cc:ce:01").
	mac = strings.ToLower(mac)
	parts := strings.Split(mac, ":")
	for i, p := range parts {
		parts[i] = strings.TrimLeft(p, "0")
		if parts[i] == "" {
			parts[i] = "0"
		}
	}
	leaseMAC := "1," + strings.Join(parts, ":")

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile("/var/db/dhcpd_leases")
		if err == nil {
			// Parse the plist-like lease file.
			lines := strings.Split(string(data), "\n")
			var currentIP string
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "ip_address=") {
					currentIP = strings.TrimPrefix(line, "ip_address=")
				}
				if strings.HasPrefix(line, "hw_address=") {
					hw := strings.TrimPrefix(line, "hw_address=")
					if strings.ToLower(hw) == leaseMAC && currentIP != "" {
						return currentIP, nil
					}
				}
				if line == "}" {
					currentIP = ""
				}
			}
		}
		time.Sleep(time.Second)
	}
	return "", fmt.Errorf("no DHCP lease for MAC %s after %v", mac, timeout)
}

// waitForSSH retries SSH connection to the given IP until it succeeds or
// the timeout expires.
func waitForSSH(ip string, timeout time.Duration) (*ssh.Client, error) {
	deadline := time.Now().Add(timeout)
	addr := net.JoinHostPort(ip, "22")
	cfg := &ssh.ClientConfig{
		User:            "admin",
		Auth:            []ssh.AuthMethod{ssh.Password("admin")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}
	for time.Now().Before(deadline) {
		sc, err := ssh.Dial("tcp", addr, cfg)
		if err == nil {
			return sc, nil
		}
		time.Sleep(time.Second)
	}
	return nil, fmt.Errorf("SSH to %s timed out after %v", addr, timeout)
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

	cfgData, err := os.ReadFile(filepath.Join(tartDir, "config.json"))
	if err != nil {
		return fmt.Errorf("reading tart config: %w", err)
	}
	var tc tartConfig
	if err := json.Unmarshal(cfgData, &tc); err != nil {
		return fmt.Errorf("parsing tart config: %w", err)
	}

	hwModel, err := base64.StdEncoding.DecodeString(tc.HardwareModel)
	if err != nil {
		return fmt.Errorf("decoding hardwareModel: %w", err)
	}
	if err := os.WriteFile(filepath.Join(cloneDir, "HardwareModel"), hwModel, 0644); err != nil {
		return err
	}

	ecid, err := base64.StdEncoding.DecodeString(tc.ECID)
	if err != nil {
		return fmt.Errorf("decoding ecid: %w", err)
	}
	if err := os.WriteFile(filepath.Join(cloneDir, "MachineIdentifier"), ecid, 0644); err != nil {
		return err
	}

	if out, err := exec.Command("cp", "-c", filepath.Join(tartDir, "disk.img"), filepath.Join(cloneDir, "Disk.img")).CombinedOutput(); err != nil {
		if out2, err2 := exec.Command("cp", filepath.Join(tartDir, "disk.img"), filepath.Join(cloneDir, "Disk.img")).CombinedOutput(); err2 != nil {
			return fmt.Errorf("copying disk: %v: %s (APFS clone: %v: %s)", err2, out2, err, out)
		}
	}

	if out, err := exec.Command("cp", "-c", filepath.Join(tartDir, "nvram.bin"), filepath.Join(cloneDir, "AuxiliaryStorage")).CombinedOutput(); err != nil {
		if out2, err2 := exec.Command("cp", filepath.Join(tartDir, "nvram.bin"), filepath.Join(cloneDir, "AuxiliaryStorage")).CombinedOutput(); err2 != nil {
			return fmt.Errorf("copying nvram: %v: %s (APFS clone: %v: %s)", err2, out2, err, out)
		}
	}

	tmCfg := struct {
		VMid         string `json:"vmID"`
		ServerSocket string `json:"serverSocket"`
		MemorySize   uint64 `json:"memorySize"`
		Mac          string `json:"mac"`
	}{
		VMid:         testID,
		ServerSocket: dgramSock,
		MemorySize:   4 * 1024 * 1024 * 1024,
		Mac:          mac,
	}
	tmData, _ := json.MarshalIndent(tmCfg, "", "  ")
	return os.WriteFile(filepath.Join(cloneDir, "config.json"), tmData, 0644)
}

// startTailMacVM restores a macOS VM from a cached snapshot and launches it
// via tailmac Host.app in headless mode, connected to vnet's dgram socket.
func (e *Env) startTailMacVM(n *Node) error {
	snapDir := e.macosSnapshot

	if err := e.ensureTailMac(); err != nil {
		return err
	}

	testID := fmt.Sprintf("vmtest-%s-%d", n.name, os.Getpid())

	// Host.app expects VM files under ~/.cache/tailscale/vmtest/macos/<id>/
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("UserHomeDir: %w", err)
	}
	vmBase := filepath.Join(home, ".cache", "tailscale", "vmtest", "macos")
	os.MkdirAll(vmBase, 0755)
	cloneDir := filepath.Join(vmBase, testID)

	// APFS clone the entire snapshot directory (includes SaveFile.vzvmsave).
	e.t.Logf("[%s] cloning snapshot -> %s", n.name, testID)
	if out, err := exec.Command("cp", "-c", "-r", snapDir, cloneDir).CombinedOutput(); err != nil {
		if out2, err2 := exec.Command("cp", "-r", snapDir, cloneDir).CombinedOutput(); err2 != nil {
			return fmt.Errorf("cloning snapshot: %v: %s (APFS clone: %v: %s)", err2, out2, err, out)
		}
	}
	e.t.Cleanup(func() { os.RemoveAll(cloneDir) })

	// Write test-specific config.json with the vnet MAC and dgram socket.
	mac := n.vnetNode.NICMac(0)
	cfg := struct {
		VMid         string `json:"vmID"`
		ServerSocket string `json:"serverSocket"`
		MemorySize   uint64 `json:"memorySize"`
		Mac          string `json:"mac"`
	}{
		VMid:         testID,
		ServerSocket: e.dgramSockAddr,
		MemorySize:   8 * 1024 * 1024 * 1024,
		Mac:          mac.String(),
	}
	cfgData, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(filepath.Join(cloneDir, "config.json"), cfgData, 0644); err != nil {
		return fmt.Errorf("writing config.json: %w", err)
	}

	// Launch Host.app with disconnected NIC + hot-swap to vnet.
	// Host.app will restore from SaveFile.vzvmsave (fast), then
	// hot-swap the NIC to the vnet dgram socket.
	hostBin := filepath.Join(e.tailmacDir, "Host.app", "Contents", "MacOS", "Host")

	// Compute the node's IP and gateway for static assignment via vsock.
	nodeIP := n.vnetNode.LanIP(n.nets[0])
	// The gateway is the network's base address (e.g. 192.168.1.1 for /24).
	// We derive it from the node IP: same /24 prefix, host part = 1.
	gwIP := nodeIP.As4()
	gwIP[3] = 1
	gateway := netip.AddrFrom4(gwIP)

	args := []string{
		"run", "--id", testID, "--headless",
		"--disconnected-nic",
		"--attach-network", e.dgramSockAddr,
		"--assign-ip", fmt.Sprintf("%s/255.255.255.0/%s", nodeIP, gateway),
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

	if wantScreenshots {
		screenshotPortCh := make(chan int, 1)
		go func() {
			scanner := bufio.NewScanner(stdoutPipe)
			for scanner.Scan() {
				line := scanner.Text()
				fmt.Fprintln(logFile, line)
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
		// Kill immediately — no need to save state for ephemeral test clones.
		cmd.Process.Kill()
		cmd.Wait()
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
