// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func toolchainRev() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getting CWD: %v", err)
	}
	d := cwd
findTopLevel:
	for {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			break findTopLevel
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("finding .git: %v", err)
		}
		d = filepath.Dir(d)
		if d == "/" {
			return "", fmt.Errorf("couldn't find .git starting from %q, cannot manage toolchain", cwd)
		}
	}

	return readRevFile(filepath.Join(d, "go.toolchain.rev"))
}

func readRevFile(path string) (string, error) {
	bs, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(bytes.TrimSpace(bs)), nil
}

func getToolchain() (toolchainDir, gorootDir string, err error) {
	cache := filepath.Join(os.Getenv("HOME"), ".cache")
	toolchainDir = filepath.Join(cache, "tailscale-go")
	gorootDir = filepath.Join(toolchainDir, "gocross-goroot")

	if err := ensureToolchain(cache, toolchainDir); err != nil {
		return "", "", err
	}
	// We put the goroot inside toolchainDir so that it gets wiped and rebuilt
	// whenever a new toolchain shows up. But we have to check and build it
	// separately from the toolchain, because gocross-wrapper.sh can download a
	// bootstrap toolchain to build gocross. This will make toolchainDir exist
	// but not gorootDir. This is also what happens during an upgrade from an
	// older gocross that didn't create a goroot, to this one.
	if err := ensureGoroot(toolchainDir, gorootDir); err != nil {
		return "", "", err
	}
	return toolchainDir, gorootDir, nil
}

func ensureToolchain(cache, toolchainDir string) error {
	stampFile := toolchainDir + ".extracted"

	wantRev, err := toolchainRev()
	if err != nil {
		return err
	}
	gotRev, err := readRevFile(stampFile)
	if err != nil {
		return fmt.Errorf("reading stamp file %q: %v", stampFile, err)
	}
	if gotRev == wantRev {
		// Toolchain already good.
		return nil
	}

	if err := os.RemoveAll(toolchainDir); err != nil {
		return err
	}
	if err := os.RemoveAll(stampFile); err != nil {
		return err
	}

	if err := downloadCachedgo(toolchainDir, wantRev); err != nil {
		return err
	}
	if err := os.WriteFile(stampFile, []byte(wantRev), 0644); err != nil {
		return err
	}

	return nil
}

func ensureGoroot(toolchainDir, gorootDir string) error {
	if _, err := os.Stat(gorootDir); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}

	if err := makeGoroot(toolchainDir, gorootDir); err != nil {
		return err
	}

	return nil
}

func downloadCachedgo(toolchainDir, toolchainRev string) error {
	url := fmt.Sprintf("https://github.com/tailscale/go/releases/download/build-%s/%s-%s.tar.gz", toolchainRev, runtime.GOOS, runtime.GOARCH)

	archivePath := toolchainDir + ".tar.gz"
	f, err := os.Create(archivePath)
	if err != nil {
		return err
	}

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to get %q: %v", url, resp.Status)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	if err := os.MkdirAll(toolchainDir, 0755); err != nil {
		return err
	}
	cmd := exec.Command("tar", "--strip-components=1", "-xf", archivePath)
	cmd.Dir = toolchainDir
	if err := cmd.Run(); err != nil {
		return err
	}

	if err := os.RemoveAll(archivePath); err != nil {
		return err
	}

	return nil
}
