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
	// gocross gets built in the root of the repo that has toolchain
	// information, so we can use os.Args[0] to locate toolchain info.
	//
	// We might be getting invoked via the synthetic goroot that we create, so
	// walk symlinks to find the true location of gocross.
	start, err := os.Executable()
	if err != nil {
		return "", err
	}
	start, err = filepath.EvalSymlinks(start)
	if err != nil {
		return "", fmt.Errorf("evaluating symlinks in %q: %v", os.Args[0], err)
	}
	start = filepath.Dir(start)
	d := start
findTopLevel:
	for {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			break findTopLevel
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("finding .git: %v", err)
		}
		d = filepath.Dir(d)
		if d == "/" {
			return "", fmt.Errorf("couldn't find .git starting from %q, cannot manage toolchain", start)
		}
	}

	return readRevFile(filepath.Join(d, "go.toolchain.rev"))
}

func readRevFile(path string) (string, error) {
	bs, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(bs)), nil
}

func getToolchain() (toolchainDir, gorootDir string, err error) {
	rev, err := toolchainRev()
	if err != nil {
		return "", "", err
	}

	cache := filepath.Join(os.Getenv("HOME"), ".cache")
	toolchainDir = filepath.Join(cache, "tsgo", rev)
	gorootDir = filepath.Join(toolchainDir, "gocross-goroot")

	// You might wonder why getting the toolchain also provisions and returns a
	// path suitable for use as GOROOT. Wonder no longer!
	//
	// A bunch of our tests and build processes involve re-invoking 'go build'
	// or other build-ish commands (install, run, ...). These typically use
	// runtime.GOROOT + "bin/go" to get at the Go binary. Even more edge case-y,
	// tailscale.com/cmd/tsconnect needs to fish a javascript glue file out of
	// GOROOT in order to build the javascript bundle for serving.
	//
	// Gocross always does a -trimpath on builds for reproducibility, which
	// wipes out the burned-in runtime.GOROOT value from the binary. This means
	// that using gocross on these various test and build processes ends up
	// breaking with mysterious path errors.
	//
	// We don't want to stop using -trimpath, or otherwise make GOROOT work in
	// "normal" builds, because that is a footgun that lets people accidentally
	// create assumptions that the build toolchain is still around at runtime.
	// Instead, we want to make 'go test' and 'go run' have access to GOROOT,
	// while still removing it from standalone binaries.
	//
	// So, construct and pass a GOROOT to the actual 'go' invocation, which lets
	// tests and build processes locate and use GOROOT. For consistency, the
	// GOROOT that's passed in is a symlink farm that mostly points to the
	// toolchain's underlying GOROOT, but 'bin/go' points back to gocross. This
	// means that if you invoke 'go test' via gocross, and that test tries to
	// build code, that build will also end up using gocross.

	if err := ensureToolchain(cache, toolchainDir); err != nil {
		return "", "", err
	}
	if err := ensureGoroot(toolchainDir, gorootDir); err != nil {
		return "", "", err
	}

	return toolchainDir, gorootDir, nil
}

func ensureToolchain(cacheDir, toolchainDir string) error {
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

	if filepath.IsAbs(wantRev) {
		// Local dev toolchain.
		if err := os.Symlink(wantRev, toolchainDir); err != nil {
			return err
		}
		return nil
	} else {
		if err := downloadCachedgo(toolchainDir, wantRev); err != nil {
			return err
		}
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
	return makeGoroot(toolchainDir, gorootDir)

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
