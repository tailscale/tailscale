// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

// TestGokrazyUpdatesItselfToSameImage exercises the Gokrazy appliance update
// path end-to-end in QEMU. It builds a GAF for the same natlab image, serves it
// from the vnet fileserver, asks the guest to install it to the inactive
// partition, then verifies the guest rebooted successfully from the other root
// partition.
func TestGokrazyUpdatesItselfToSameImage(t *testing.T) {
	env := vmtest.New(t)

	wan := env.AddNetwork("1.0.0.1", "192.168.1.1/24", vnet.EasyNAT)
	node := env.AddNode("gokrazy", wan,
		vmtest.OS(vmtest.Gokrazy),
		vmtest.DontJoinTailnet())

	env.Start()

	gaf := buildNatlabGAF(t)
	env.RegisterFile("natlabapp.gaf", gaf)

	rootBefore, err := env.GokrazyRoot(node)
	if err != nil {
		t.Fatalf("getting initial gokrazy root: %v", err)
	}
	t.Logf("initial gokrazy root: %s", rootBefore)

	out, err := env.Tailscale(node,
		"update",
		"--",
		"--gokrazy-update-from-url=http://files.tailscale/natlabapp.gaf",
		"--unsigned",
	)
	if err != nil {
		if errors.Is(err, io.EOF) {
			t.Logf("update command connection ended during reboot: %v", err)
		} else {
			t.Fatalf("gokrazy update command failed: %v\n%s", err, out)
		}
	} else {
		t.Logf("update command output:\n%s", out)
	}

	if err := tstest.WaitFor(90*time.Second, func() error {
		rootAfter, err := env.GokrazyRoot(node)
		if err != nil {
			return err
		}
		if rootAfter == rootBefore {
			return fmt.Errorf("still booted with root %q", rootAfter)
		}
		t.Logf("updated gokrazy root: %s", rootAfter)
		return nil
	}); err != nil {
		t.Fatalf("waiting for gokrazy to reboot into inactive partition: %v", err)
	}
}

func buildNatlabGAF(t *testing.T) []byte {
	t.Helper()

	modRoot := moduleRoot(t)
	gafPath := filepath.Join(modRoot, "gokrazy", "natlabapp.gaf")
	t.Cleanup(func() { os.Remove(gafPath) })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "run", "build.go", "--gaf", "--app=natlabapp")
	cmd.Dir = filepath.Join(modRoot, "gokrazy")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("building natlabapp.gaf: %v\n%s", err, out.String())
	}
	t.Logf("built natlabapp.gaf:\n%s", out.String())

	gaf, err := os.ReadFile(gafPath)
	if err != nil {
		t.Fatalf("reading %s: %v", gafPath, err)
	}
	return gaf
}

func moduleRoot(t *testing.T) string {
	t.Helper()

	out, err := exec.Command("go", "env", "GOMOD").CombinedOutput()
	if err != nil {
		t.Fatalf("go env GOMOD: %v\n%s", err, out)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == os.DevNull {
		t.Fatal("not in a Go module")
	}
	return filepath.Dir(gomod)
}
