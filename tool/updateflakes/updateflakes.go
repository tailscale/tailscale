// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// updateflakes regenerates flakehashes.json, the file that records
// the Nix SRI hashes for the Go module vendor tree and the Tailscale
// Go toolchain tarball.
//
// The file is content-addressed: each block records the input
// fingerprint that produced its SRI, and updateflakes only
// regenerates a block when the current input differs from the
// recorded fingerprint. As a result, repeat runs with no input
// changes are no-ops.
//
// Run from the repo root:
//
//	./tool/go run ./tool/updateflakes
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sync/errgroup"
	"tailscale.com/cmd/nardump/nardump"
)

const (
	hashesFile       = "flakehashes.json"
	goModFile        = "go.mod"
	goSumFile        = "go.sum"
	toolchainRevFile = "go.toolchain.rev"
	flakeNixFile     = "flake.nix"
	shellNixFile     = "shell.nix"
	cacheBustPrefix  = "# nix-direnv cache busting line:"
)

// FlakeHashes is the on-disk schema of flakehashes.json. It is also
// consumed directly by flake.nix via builtins.fromJSON, so changes
// to the JSON shape must be coordinated with flake.nix.
type FlakeHashes struct {
	Toolchain ToolchainHash `json:"toolchain"`
	Vendor    VendorHash    `json:"vendor"`
}

// ToolchainHash records the SRI of the Tailscale Go toolchain
// tarball. Rev is the value in go.toolchain.rev that produced SRI.
type ToolchainHash struct {
	Rev string `json:"rev"`
	SRI string `json:"sri"`
}

// VendorHash records the SRI of `go mod vendor` output. GoModSum is a
// fingerprint of go.mod and go.sum that produced SRI.
type VendorHash struct {
	GoModSum string `json:"goModSum"`
	SRI      string `json:"sri"`
}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	have, err := loadHashes()
	if err != nil {
		return err
	}
	want := have

	rev, err := readTrim(toolchainRevFile)
	if err != nil {
		return err
	}
	wantToolchain := have.Toolchain.Rev != rev || have.Toolchain.SRI == ""

	goModSum, err := goModFingerprint()
	if err != nil {
		return err
	}
	wantVendor := have.Vendor.GoModSum != goModSum || have.Vendor.SRI == ""

	var (
		newToolchain ToolchainHash
		newVendor    VendorHash
	)
	var g errgroup.Group
	if wantToolchain {
		g.Go(func() error {
			sri, err := hashToolchain(rev)
			if err != nil {
				return err
			}
			newToolchain = ToolchainHash{Rev: rev, SRI: sri}
			return nil
		})
	}
	if wantVendor {
		g.Go(func() error {
			sri, err := hashVendor()
			if err != nil {
				return err
			}
			newVendor = VendorHash{GoModSum: goModSum, SRI: sri}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}
	if wantToolchain {
		want.Toolchain = newToolchain
	}
	if wantVendor {
		want.Vendor = newVendor
	}

	if want != have {
		if err := writeHashes(want); err != nil {
			return err
		}
	}

	// nix-direnv only watches the top-level nix files for changes,
	// so when a referenced hash changes we must also tickle
	// flake.nix and shell.nix to force re-evaluation.
	for _, f := range []string{flakeNixFile, shellNixFile} {
		if err := updateCacheBust(f, want.Vendor.SRI); err != nil {
			return err
		}
	}
	return nil
}

func loadHashes() (FlakeHashes, error) {
	var h FlakeHashes
	data, err := os.ReadFile(hashesFile)
	if errors.Is(err, fs.ErrNotExist) {
		return h, nil
	}
	if err != nil {
		return h, err
	}
	if err := json.Unmarshal(data, &h); err != nil {
		return h, fmt.Errorf("parse %s: %w", hashesFile, err)
	}
	return h, nil
}

func writeHashes(h FlakeHashes) error {
	b, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(hashesFile, b, 0644)
}

func readTrim(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// goModFingerprint returns a content fingerprint of go.mod and go.sum
// that changes whenever either file changes.
func goModFingerprint() (string, error) {
	h := sha256.New()
	for _, f := range []string{goModFile, goSumFile} {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s %d\n", f, len(b))
		h.Write(b)
	}
	return "sha256-" + base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

func hashVendor() (string, error) {
	out, err := os.MkdirTemp("", "nar-vendor-")
	if err != nil {
		return "", err
	}
	// `go mod vendor -o` requires the destination to not already exist.
	if err := os.Remove(out); err != nil {
		return "", err
	}
	defer os.RemoveAll(out)

	cmd := exec.Command("./tool/go", "mod", "vendor", "-o", out)
	cmd.Env = append(os.Environ(), "GOWORK=off")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("go mod vendor: %w", err)
	}
	return nardump.SRI(os.DirFS(out))
}

func hashToolchain(rev string) (string, error) {
	out, err := os.MkdirTemp("", "nar-toolchain-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(out)

	url := fmt.Sprintf("https://github.com/tailscale/go/archive/%s.tar.gz", rev)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching %s: %s", url, resp.Status)
	}

	tar := exec.Command("tar", "-xz", "-C", out)
	tar.Stdin = resp.Body
	tar.Stderr = os.Stderr
	if err := tar.Run(); err != nil {
		return "", fmt.Errorf("extracting toolchain tarball: %w", err)
	}
	return nardump.SRI(os.DirFS(filepath.Join(out, "go-"+rev)))
}

// updateCacheBust rewrites the "# nix-direnv cache busting line"
// in path to embed sri so nix-direnv re-evaluates when the SRI
// changes. The line lives at end of file, so walk in reverse.
func updateCacheBust(path, sri string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	want := []byte(cacheBustPrefix + " " + sri)
	lines := bytes.Split(b, []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if !bytes.HasPrefix(line, []byte(cacheBustPrefix)) {
			continue
		}
		if bytes.Equal(line, want) {
			return nil
		}
		lines[i] = want
		return os.WriteFile(path, bytes.Join(lines, []byte("\n")), 0644)
	}
	return fmt.Errorf("%s: missing %q line", path, cacheBustPrefix)
}
