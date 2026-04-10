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
// The VM is created at ~/.cache/tailscale/vmtest/macos/<name>/. The IPSW
// restore image is cached in ~/.cache/tailscale/vmtest/macos-ipsw/ and
// only re-downloaded when Apple publishes a newer version.
//
// This only runs on macOS arm64 (Apple Silicon) and requires the Virtualization
// framework entitlement, so the helper Swift binary is compiled and ad-hoc signed
// automatically.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var (
	vmName  = flag.String("name", "macos-base", "VM name (directory under ~/.cache/tailscale/vmtest/macos/)")
	rebuild = flag.Bool("rebuild", false, "delete existing VM and recreate it")
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
	cacheBase := filepath.Join(home, ".cache", "tailscale", "vmtest")
	vmDir := filepath.Join(cacheBase, "macos", *vmName)
	ipswDir := filepath.Join(cacheBase, "macos-ipsw")

	if _, err := os.Stat(filepath.Join(vmDir, "Disk.img")); err == nil {
		if !*rebuild {
			log.Printf("VM %q already exists at %s; nothing to do. Use --rebuild to recreate.", *vmName, vmDir)
			return
		}
		log.Printf("Removing existing VM %q...", *vmName)
		if err := os.RemoveAll(vmDir); err != nil {
			log.Fatalf("Removing %s: %v", vmDir, err)
		}
	}

	os.MkdirAll(vmDir, 0755)
	os.MkdirAll(ipswDir, 0755)

	// Step 1: Build the Swift helper.
	log.Println("Building macOS VM installer helper...")
	helperBin, err := buildSwiftHelper()
	if err != nil {
		log.Fatalf("Building Swift helper: %v", err)
	}
	defer os.RemoveAll(filepath.Dir(helperBin))

	// Step 2: Get the latest IPSW URL from Apple via the VZ framework.
	log.Println("Checking for latest macOS restore image...")
	out, err := exec.Command(helperBin, "fetch-ipsw-url").Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			log.Fatalf("Fetching IPSW URL: %v\n%s", err, ee.Stderr)
		}
		log.Fatalf("Fetching IPSW URL: %v", err)
	}
	ipswURL := strings.TrimSpace(string(out))
	log.Printf("Latest IPSW: %s", ipswURL)

	// Step 3: Download the IPSW, using the cached copy if unchanged.
	ipswPath, err := ensureIPSW(ipswDir, ipswURL)
	if err != nil {
		log.Fatalf("Downloading IPSW: %v", err)
	}

	// Step 4: Install macOS from the IPSW.
	log.Printf("Installing macOS into %s (this takes a few minutes)...", vmDir)
	cmd := exec.Command(helperBin, "install", vmDir, ipswPath)
	cmd.Stdout = os.Stderr // Swift helper prints progress to stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("macOS installation failed: %v", err)
	}

	// Step 5: Write config.json for the tailmac Host.app.
	configJSON := fmt.Sprintf(`{
  "vmID": %q,
  "serverSocket": "/tmp/qemu-dgram.sock",
  "memorySize": 8589934592,
  "mac": "52:cc:cc:cc:cc:01",
  "ethermac": "52:cc:cc:cc:ce:01",
  "port": 51009
}`, *vmName)
	if err := os.WriteFile(filepath.Join(vmDir, "config.json"), []byte(configJSON), 0644); err != nil {
		log.Fatalf("Writing config.json: %v", err)
	}

	// Step 6: Mount the disk and apply post-install fixups.
	log.Println("Applying post-install fixups (skipping Setup Assistant)...")
	if err := applyPostInstallFixups(vmDir); err != nil {
		log.Fatalf("Post-install fixups: %v", err)
	}

	log.Printf("macOS VM %q created successfully at %s", *vmName, vmDir)
	log.Println("Run vmtest tests with: go test ./tstest/natlab/vmtest/ --run-vm-tests -v -run TestMacOS")
}

// ensureIPSW downloads the IPSW to ipswDir if it's not already cached or if
// the remote version has changed. Only one IPSW is kept in the directory.
// Returns the path to the local IPSW file.
func ensureIPSW(ipswDir, ipswURL string) (string, error) {
	// Use the filename from the URL (e.g. "UniversalMac_26.4.1_25E253_Restore.ipsw").
	urlBase := filepath.Base(ipswURL)
	if urlBase == "" || urlBase == "." || urlBase == "/" {
		urlBase = "Restore.ipsw"
	}
	localPath := filepath.Join(ipswDir, urlBase)

	// If we already have this exact file, do a conditional GET to check freshness.
	if fi, err := os.Stat(localPath); err == nil && fi.Size() > 0 {
		fresh, err := checkIPSWFresh(localPath, ipswURL)
		if err != nil {
			log.Printf("Warning: freshness check failed, using cached IPSW: %v", err)
			return localPath, nil
		}
		if fresh {
			log.Printf("Using cached IPSW at %s (%d MB)", localPath, fi.Size()/1024/1024)
			return localPath, nil
		}
		log.Println("Cached IPSW is stale, re-downloading...")
	}

	// Remove any other .ipsw files in the directory (keep at most one).
	entries, _ := os.ReadDir(ipswDir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".ipsw") || strings.HasSuffix(e.Name(), ".ipsw.etag") {
			os.Remove(filepath.Join(ipswDir, e.Name()))
		}
	}

	log.Printf("Downloading %s (~15GB)...", ipswURL)
	tmpPath := localPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return "", err
	}
	defer func() {
		f.Close()
		os.Remove(tmpPath)
	}()

	resp, err := http.Get(ipswURL)
	if err != nil {
		return "", fmt.Errorf("HTTP GET: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %s", resp.Status)
	}

	total := resp.ContentLength
	pr := &progressReader{r: resp.Body, total: total}
	if _, err := io.Copy(f, pr); err != nil {
		return "", fmt.Errorf("downloading: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpPath, localPath); err != nil {
		return "", err
	}

	// Save the ETag for future freshness checks.
	if etag := resp.Header.Get("ETag"); etag != "" {
		os.WriteFile(localPath+".etag", []byte(etag), 0644)
	}

	log.Printf("Downloaded IPSW to %s", localPath)
	return localPath, nil
}

// checkIPSWFresh does a HEAD request with If-None-Match (ETag) to see if
// the cached IPSW is still current. Returns true if the cache is fresh.
func checkIPSWFresh(localPath, ipswURL string) (bool, error) {
	req, err := http.NewRequest("HEAD", ipswURL, nil)
	if err != nil {
		return false, err
	}
	if etag, err := os.ReadFile(localPath + ".etag"); err == nil && len(etag) > 0 {
		req.Header.Set("If-None-Match", string(etag))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusNotModified, nil
}

type progressReader struct {
	r     io.Reader
	total int64
	read  int64
	last  int // last printed percent
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.r.Read(p)
	pr.read += int64(n)
	if pr.total > 0 {
		pct := int(pr.read * 100 / pr.total)
		if pct != pr.last {
			pr.last = pct
			if pct%5 == 0 {
				log.Printf("  download: %d%% (%d / %d MB)", pct, pr.read/1024/1024, pr.total/1024/1024)
			}
		}
	}
	return n, err
}

// buildSwiftHelper compiles and signs the embedded Swift installer program.
func buildSwiftHelper() (string, error) {
	tmpDir, err := os.MkdirTemp("", "build-macos-vm-*")
	if err != nil {
		return "", err
	}

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
	candidates := []string{
		"tstest/build-macos-base-vm",
		".",
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "install.swift")); err == nil {
			return filepath.Abs(c)
		}
	}
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

	out, err := exec.Command("hdiutil", "attach", diskPath, "-nomount").CombinedOutput()
	if err != nil {
		return fmt.Errorf("hdiutil attach: %v\n%s", err, out)
	}

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

	// Wait for the APFS Data volume to appear. After hdiutil attach,
	// the kernel synthesizes APFS volumes asynchronously.
	var dataVolDev string
	if err := waitFor(10*time.Second, func() error {
		out, _ := exec.Command("diskutil", "list").CombinedOutput()
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "APFS Volume") && strings.Contains(line, "Data") {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					dataVolDev = fields[len(fields)-1]
					return nil
				}
			}
		}
		return fmt.Errorf("APFS Data volume not yet available")
	}); err != nil {
		return fmt.Errorf("waiting for APFS Data volume: %w", err)
	}

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

	dbDir := filepath.Join(mountPoint, "private", "var", "db")
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return fmt.Errorf("creating var/db: %v", err)
	}
	setupDone := filepath.Join(dbDir, ".AppleSetupDone")
	if err := os.WriteFile(setupDone, nil, 0644); err != nil {
		return fmt.Errorf("creating .AppleSetupDone: %v", err)
	}
	log.Printf("Created %s", setupDone)

	return nil
}

func waitFor(timeout time.Duration, try func() error) error {
	deadline := time.Now().Add(timeout)
	for {
		err := try()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(200 * time.Millisecond)
	}
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
