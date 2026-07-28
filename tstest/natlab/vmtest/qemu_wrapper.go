// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package vmtest

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// Re-exec'd as a wrapper around QEMU: when the test process dies (any
// reason, including SIGKILL), the kernel closes the pipe write end, the
// wrapper sees EOF, and kills QEMU's process group.

const wrapperEnv = "TS_VMTEST_QEMU_WRAPPER"

func init() {
	if os.Getenv(wrapperEnv) == "" {
		return
	}
	runQEMUWrapper()
}

func runQEMUWrapper() {
	fd, err := strconv.Atoi(os.Getenv(wrapperEnv))
	if err != nil {
		log.Fatalf("vmtest qemu wrapper: bad %s: %v", wrapperEnv, err)
	}
	os.Unsetenv(wrapperEnv)
	if len(os.Args) < 2 {
		log.Fatalf("vmtest qemu wrapper: missing command")
	}
	pipeFd := os.NewFile(uintptr(fd), "parent-pipe")

	// QEMU inherits our pgid (the test set Setpgid on us), so a group kill
	// from the test reaches QEMU too. Don't set Setpgid here.
	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		log.Fatalf("vmtest qemu wrapper: %v", err)
	}

	go func() {
		// Block until the parent's pipe write end closes (EOF), then kill
		// our process group (which includes QEMU and any of its children).
		io.Copy(io.Discard, pipeFd)
		syscall.Kill(0, syscall.SIGKILL)
	}()

	cmd.Wait()
}

// killWithParent rewrites cmd to run via a wrapper that kills it if the
// test process dies. The returned *os.File must be kept alive until the
// command is no longer needed; closing it makes the wrapper exit.
func killWithParent(cmd *exec.Cmd) (*os.File, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("os.Executable: %w", err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("pipe: %w", err)
	}

	cmd.ExtraFiles = append(cmd.ExtraFiles, r)
	pipeFd := 3 + len(cmd.ExtraFiles) - 1 // stdin/stdout/stderr + ExtraFiles index
	cmd.Args = append([]string{self, cmd.Path}, cmd.Args[1:]...)
	cmd.Path = self
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%d", wrapperEnv, pipeFd))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	return w, nil
}

// killProcessTree SIGKILLs cmd's process group (cmd plus any descendants
// that didn't escape it).
func killProcessTree(cmd *exec.Cmd) error {
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
