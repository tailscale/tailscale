// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Command build-macos-base-vm creates a macOS VM image suitable for use
// with the vmtest integration test framework. It downloads a macOS IPSW
// restore image, installs macOS into a VM, and applies post-install fixups
// so the VM boots to a usable state without the interactive Setup Assistant.
//
// Usage:
//
//	go run ./tstest/build-macos-base-vm
//
// The VM is created at ~/VM.bundle/llmacstation/ and can be used by vmtest
// tests that include macOS nodes. The IPSW is cached at ~/VM.bundle/RestoreImage.ipsw.
//
// This only runs on macOS arm64 (Apple Silicon) and requires the Virtualization
// framework entitlement, so the helper Swift binary is compiled and ad-hoc signed
// automatically.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var (
	vmName = flag.String("name", "llmacstation", "VM name (directory under ~/VM.bundle/)")
)

func main() {
	flag.Parse()
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		log.Fatal("This program only runs on macOS arm64 (Apple Silicon).")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	bundleDir := filepath.Join(home, "VM.bundle")
	vmDir := filepath.Join(bundleDir, *vmName)
	ipswPath := filepath.Join(bundleDir, "RestoreImage.ipsw")

	if _, err := os.Stat(filepath.Join(vmDir, "Disk.img")); err == nil {
		log.Fatalf("VM %q already exists at %s. Delete it first or choose a different --name.", *vmName, vmDir)
	}

	os.MkdirAll(bundleDir, 0755)
	os.MkdirAll(vmDir, 0755)

	// Step 1: Build the Swift helper that does the VZ install.
	log.Println("Building macOS VM installer helper...")
	helperBin, err := buildSwiftHelper()
	if err != nil {
		log.Fatalf("Building Swift helper: %v", err)
	}
	defer os.RemoveAll(filepath.Dir(helperBin))

	// Step 2: Run the helper to download IPSW (if needed) and install macOS.
	log.Printf("Installing macOS into %s...", vmDir)
	log.Println("(This downloads ~15GB on first run and takes several minutes to install.)")
	cmd := exec.Command(helperBin, vmDir, ipswPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("macOS installation failed: %v", err)
	}

	// Step 3: Write config.json.
	configJSON := fmt.Sprintf(`{
  "vmName": %q,
  "memorySize": 8589934592,
  "diskSize": 77309411328,
  "mac": "52:cc:cc:cc:cc:01",
  "hostname": %q
}`, *vmName, *vmName)
	if err := os.WriteFile(filepath.Join(vmDir, "config.json"), []byte(configJSON), 0644); err != nil {
		log.Fatalf("Writing config.json: %v", err)
	}

	// Step 4: Mount the disk and apply post-install fixups.
	log.Println("Applying post-install fixups (skipping Setup Assistant)...")
	if err := applyPostInstallFixups(vmDir); err != nil {
		log.Fatalf("Post-install fixups: %v", err)
	}

	log.Printf("macOS VM %q created successfully at %s", *vmName, vmDir)
	log.Println("Run vmtest tests with: go test ./tstest/natlab/vmtest/ --run-vm-tests -v -run TestMacOS")
}

// buildSwiftHelper compiles and signs the embedded Swift installer program.
func buildSwiftHelper() (string, error) {
	tmpDir, err := os.MkdirTemp("", "build-macos-vm-*")
	if err != nil {
		return "", err
	}

	// Find the Swift source file next to this Go file.
	// When run via "go run", we need to find it relative to the source.
	srcDir, err := findSourceDir()
	if err != nil {
		return "", fmt.Errorf("finding source dir: %w", err)
	}
	swiftSrc := filepath.Join(srcDir, "install.swift")
	if _, err := os.Stat(swiftSrc); err != nil {
		return "", fmt.Errorf("Swift source not found at %s: %w", swiftSrc, err)
	}

	binPath := filepath.Join(tmpDir, "installer")
	out, err := exec.Command("swiftc", "-O", "-o", binPath,
		"-framework", "Virtualization", swiftSrc).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("swiftc: %v\n%s", err, out)
	}

	// Sign with the virtualization entitlement.
	entPath := filepath.Join(tmpDir, "entitlements.plist")
	if err := os.WriteFile(entPath, []byte(entitlementsPlist), 0644); err != nil {
		return "", err
	}
	out, err = exec.Command("codesign", "--force", "--sign", "-",
		"--entitlements", entPath, binPath).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("codesign: %v\n%s", err, out)
	}

	return binPath, nil
}

func findSourceDir() (string, error) {
	// Try relative to the working directory first.
	candidates := []string{
		"tstest/build-macos-base-vm",
		".",
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "install.swift")); err == nil {
			return filepath.Abs(c)
		}
	}
	// Try relative to the Go module root.
	out, err := exec.Command("go", "env", "GOMOD").CombinedOutput()
	if err == nil {
		modRoot := filepath.Dir(strings.TrimSpace(string(out)))
		p := filepath.Join(modRoot, "tstest", "build-macos-base-vm")
		if _, err := os.Stat(filepath.Join(p, "install.swift")); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("cannot find install.swift")
}

// applyPostInstallFixups mounts the VM's disk image and modifies the
// filesystem so macOS boots without the Setup Assistant.
func applyPostInstallFixups(vmDir string) error {
	diskPath := filepath.Join(vmDir, "Disk.img")

	// Attach the disk image without auto-mounting.
	out, err := exec.Command("hdiutil", "attach", diskPath, "-nomount").CombinedOutput()
	if err != nil {
		return fmt.Errorf("hdiutil attach: %v\n%s", err, out)
	}

	// Parse the top-level disk device from output (e.g. /dev/disk4).
	var diskDev string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 1 && strings.HasPrefix(fields[0], "/dev/disk") {
			if diskDev == "" {
				diskDev = fields[0]
			}
		}
	}
	if diskDev == "" {
		return fmt.Errorf("no disk device found in hdiutil output:\n%s", out)
	}
	defer func() {
		exec.Command("hdiutil", "detach", diskDev, "-force").Run()
	}()

	// Wait for APFS volumes to synthesize.
	time.Sleep(2 * time.Second)

	// Find the APFS Data volume. It's on a synthesized disk derived from
	// the physical APFS container.
	var dataVolDev string
	allDisks, _ := exec.Command("diskutil", "list").CombinedOutput()
	for _, line := range strings.Split(string(allDisks), "\n") {
		if strings.Contains(line, "APFS Volume") && strings.Contains(line, "Data") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				dataVolDev = fields[len(fields)-1]
			}
		}
	}
	if dataVolDev == "" {
		return fmt.Errorf("no APFS Data volume found:\n%s", allDisks)
	}

	// Mount the Data volume via diskutil (handles APFS permissions correctly).
	mountPoint, err := os.MkdirTemp("", "vm-data-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(mountPoint)

	out, err = exec.Command("diskutil", "mount", "-mountPoint", mountPoint, dataVolDev).CombinedOutput()
	if err != nil {
		return fmt.Errorf("mounting Data volume %s: %v\n%s", dataVolDev, err, out)
	}
	defer exec.Command("diskutil", "unmount", mountPoint).Run()

	// Create .AppleSetupDone to skip the Setup Assistant.
	setupDone := filepath.Join(mountPoint, "private", "var", "db", ".AppleSetupDone")
	if err := os.WriteFile(setupDone, nil, 0644); err != nil {
		return fmt.Errorf("creating .AppleSetupDone: %v", err)
	}
	log.Printf("Created %s", setupDone)

	return nil
}

const entitlementsPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.virtualization</key>
	<true/>
</dict>
</plist>
`
