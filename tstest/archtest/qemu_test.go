// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// This file previously had "!race" in its build constraint, which was a CI
// optimization (qemu binaries aren't installed on the race builder to save
// time). The constraint was removed because it's not a technical requirement:
// the test gracefully skips architectures when qemu-{arch} isn't available.

//go:build linux && amd64

package archtest

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"tailscale.com/util/cibuild"
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
	inCI := cibuild.On()
	for _, arch := range arches {
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
			cmd := exec.Command("go",
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
