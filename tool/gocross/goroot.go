// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// makeGoroot constructs a GOROOT-like file structure in outPath,
// which consists of toolchainRoot except for the `go` binary, which
// points to gocross.
//
// It's useful for integrating with tooling that expects to be handed
// a GOROOT, like the Goland IDE or depaware.
func makeGoroot(toolchainRoot, outPath string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("getting gocross's path: %v", err)
	}

	os.RemoveAll(outPath)
	if err := os.MkdirAll(filepath.Join(outPath, "bin"), 0750); err != nil {
		return fmt.Errorf("making %q: %v", outPath, err)
	}
	if err := os.Symlink(self, filepath.Join(outPath, "bin/go")); err != nil {
		return fmt.Errorf("linking gocross into outpath: %v", err)
	}

	if err := linkFarm(toolchainRoot, outPath); err != nil {
		return fmt.Errorf("creating GOROOT link farm: %v", err)
	}
	if err := linkFarm(filepath.Join(toolchainRoot, "bin"), filepath.Join(outPath, "bin")); err != nil {
		return fmt.Errorf("creating GOROOT/bin link farm: %v", err)
	}

	return nil
}

// linkFarm symlinks every entry in srcDir into outDir, unless that
// directory entry already exists.
func linkFarm(srcDir, outDir string) error {
	ents, err := os.ReadDir(srcDir)
	if err != nil {
		return fmt.Errorf("reading %q: %v", srcDir, err)
	}

	for _, ent := range ents {
		dst := filepath.Join(outDir, ent.Name())
		_, err := os.Lstat(dst)
		if errors.Is(err, fs.ErrNotExist) {
			if err := os.Symlink(filepath.Join(srcDir, ent.Name()), dst); err != nil {
				return fmt.Errorf("symlinking %q to %q: %v", ent.Name(), outDir, err)
			}
		} else if err != nil {
			return fmt.Errorf("stat-ing %q: %v", dst, err)
		}
	}

	return nil
}
