// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ulikunitz/xz"
)

// OSImage describes a VM operating system image.
type OSImage struct {
	Name      string
	URL       string // download URL for the cloud image
	SHA256    string // expected SHA256 hash of the image (of the final qcow2, after any decompression)
	MemoryMB  int    // RAM for the VM
	IsGokrazy bool   // true for gokrazy images (different QEMU setup)
}

// GOOS returns the Go OS name for this image.
func (img OSImage) GOOS() string {
	if img.IsGokrazy {
		return "linux"
	}
	if strings.HasPrefix(img.Name, "freebsd") {
		return "freebsd"
	}
	return "linux"
}

// GOARCH returns the Go architecture name for this image.
func (img OSImage) GOARCH() string {
	return "amd64"
}

var (
	// Gokrazy is a minimal Tailscale appliance image built from the gokrazy/natlabapp directory.
	Gokrazy = OSImage{
		Name:      "gokrazy",
		IsGokrazy: true,
		MemoryMB:  384,
	}

	// Ubuntu2404 is Ubuntu 24.04 LTS (Noble Numbat) cloud image.
	Ubuntu2404 = OSImage{
		Name:     "ubuntu-24.04",
		URL:      "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
		MemoryMB: 1024,
	}

	// Debian12 is Debian 12 (Bookworm) generic cloud image.
	Debian12 = OSImage{
		Name:     "debian-12",
		URL:      "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2",
		MemoryMB: 1024,
	}

	// FreeBSD150 is FreeBSD 15.0-RELEASE with BASIC-CLOUDINIT (nuageinit) support.
	// The image is distributed as xz-compressed qcow2.
	FreeBSD150 = OSImage{
		Name:     "freebsd-15.0",
		URL:      "https://download.freebsd.org/releases/VM-IMAGES/15.0-RELEASE/amd64/Latest/FreeBSD-15.0-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz",
		MemoryMB: 1024,
	}
)

// imageCacheDir returns the directory for cached VM images.
func imageCacheDir() string {
	if d := os.Getenv("VMTEST_CACHE_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "tailscale", "vmtest", "images")
}

// ensureImage downloads and caches the OS image if not already present.
func ensureImage(ctx context.Context, img OSImage) error {
	if img.IsGokrazy {
		return nil // gokrazy images are handled separately
	}

	cacheDir := imageCacheDir()
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return err
	}

	// Use a filename based on the image name.
	cachedPath := filepath.Join(cacheDir, img.Name+".qcow2")
	if _, err := os.Stat(cachedPath); err == nil {
		// If we have a SHA256 to verify, check it.
		if img.SHA256 != "" {
			if err := verifySHA256(cachedPath, img.SHA256); err != nil {
				log.Printf("cached image %s failed SHA256 check, re-downloading: %v", img.Name, err)
				os.Remove(cachedPath)
			} else {
				return nil
			}
		} else {
			return nil // exists, no hash to verify
		}
	}

	isXZ := strings.HasSuffix(img.URL, ".xz")
	log.Printf("downloading %s from %s...", img.Name, img.URL)

	req, err := http.NewRequestWithContext(ctx, "GET", img.URL, nil)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", img.Name, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", img.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("downloading %s: HTTP %s", img.Name, resp.Status)
	}

	// Set up the reader pipeline: HTTP body → (optional xz decompress) → file.
	var src io.Reader = resp.Body
	if isXZ {
		xzr, err := xz.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("creating xz reader for %s: %w", img.Name, err)
		}
		src = xzr
	}

	tmpFile := cachedPath + ".tmp"
	f, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	defer func() {
		f.Close()
		os.Remove(tmpFile)
	}()

	h := sha256.New()
	w := io.MultiWriter(f, h)
	if _, err := io.Copy(w, src); err != nil {
		return fmt.Errorf("downloading %s: %w", img.Name, err)
	}
	if err := f.Close(); err != nil {
		return err
	}

	if img.SHA256 != "" {
		got := hex.EncodeToString(h.Sum(nil))
		if got != img.SHA256 {
			return fmt.Errorf("SHA256 mismatch for %s: got %s, want %s", img.Name, got, img.SHA256)
		}
	}

	if err := os.Rename(tmpFile, cachedPath); err != nil {
		return err
	}
	log.Printf("downloaded %s", img.Name)
	return nil
}

// verifySHA256 checks that the file at path has the expected SHA256 hash.
func verifySHA256(path, expected string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != expected {
		return fmt.Errorf("got %s, want %s", got, expected)
	}
	return nil
}

// cachedImagePath returns the filesystem path to the cached image for the given OS.
func cachedImagePath(img OSImage) string {
	return filepath.Join(imageCacheDir(), img.Name+".qcow2")
}

// createOverlay creates a qcow2 overlay image on top of the given base image.
func createOverlay(base, overlay string) error {
	out, err := exec.Command("qemu-img", "create",
		"-f", "qcow2",
		"-F", "qcow2",
		"-b", base,
		overlay).CombinedOutput()
	if err != nil {
		return fmt.Errorf("qemu-img create overlay: %v: %s", err, out)
	}
	return nil
}
