// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux && amd64 && !race
// +build linux,amd64,!race

package archtest

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInQemu(t *testing.T) {
	t.Parallel()
	type Arch struct {
		Goarch string // GOARCH value
		Qarch  string // qemu name
	}
	arches := []Arch{
		{"arm", "arm"},
		{"arm64", "aarch64"},
		{"mips", "mips"},
		{"mipsle", "mipsel"},
		{"mips64", "mips64"},
		{"mips64le", "mips64el"},
		{"386", "386"},
	}
	inCI := os.Getenv("CI") == "true"
	for _, arch := range arches {
		arch := arch
		t.Run(arch.Goarch, func(t *testing.T) {
			t.Parallel()
			qemuUser := "qemu-" + arch.Qarch
			execVia := qemuUser
			if arch.Goarch == "386" {
				execVia = "" // amd64 can run it fine
			} else {
				look, err := exec.LookPath(qemuUser)
				if err != nil {
					if inCI {
						t.Fatalf("in CI and qemu not available: %v", err)
					}
					t.Skipf("%s not found; skipping test. error was: %v", qemuUser, err)
				}
				t.Logf("using %v", look)
			}
			cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"),
				"test",
				"--exec="+execVia,
				"-v",
				"tailscale.com/tstest/archtest",
			)
			cmd.Env = append(os.Environ(), "GOARCH="+arch.Goarch)
			out, err := cmd.CombinedOutput()
			if err != nil {
				if strings.Contains(string(out), "fatal error: sigaction failed") && !inCI {
					t.Skip("skipping; qemu too old. use 5.x.")
				}
				t.Errorf("failed: %s", out)
			}
			sub := fmt.Sprintf("I am linux/%s", arch.Goarch)
			if !bytes.Contains(out, []byte(sub)) {
				t.Errorf("output didn't contain %q: %s", sub, out)
			}
		})
	}
}
