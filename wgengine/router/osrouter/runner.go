// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package osrouter

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// commandRunner abstracts helpers to run OS commands. It exists
// purely to swap out osCommandRunner (below) with a fake runner in
// tests.
type commandRunner interface {
	run(...string) error
	output(...string) ([]byte, error)
}

type osCommandRunner struct {
	// ambientCapNetAdmin determines whether commands are executed with
	// CAP_NET_ADMIN.
	// CAP_NET_ADMIN is required when running as non-root and executing cmds
	// like `ip rule`. Even if our process has the capability, we need to
	// explicitly grant it to the new process.
	// We specifically need this for Synology DSM7 where tailscaled no longer
	// runs as root.
	ambientCapNetAdmin bool
}

// errCode extracts and returns the process exit code from err, or
// zero if err is nil.
func errCode(err error) int {
	if err == nil {
		return 0
	}
	var e *exec.ExitError
	if ok := errors.As(err, &e); ok {
		return e.ExitCode()
	}
	s := err.Error()
	if strings.HasPrefix(s, "exitcode:") {
		code, err := strconv.Atoi(s[9:])
		if err == nil {
			return code
		}
	}
	return -42
}

func (o osCommandRunner) run(args ...string) error {
	_, err := o.output(args...)
	return err
}

func (o osCommandRunner) output(args ...string) ([]byte, error) {
	if len(args) == 0 {
		return nil, errors.New("cmd: no argv[0]")
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	if o.ambientCapNetAdmin {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			AmbientCaps: []uintptr{unix.CAP_NET_ADMIN},
		}
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("running %q failed: %w\n%s", strings.Join(args, " "), err, out)
	}

	return out, nil
}

type runGroup struct {
	OkCode []int         // error codes that are acceptable, other than 0, if any
	Runner commandRunner // the runner that actually runs our commands
	ErrAcc error         // first error encountered, if any
}

func newRunGroup(okCode []int, runner commandRunner) *runGroup {
	return &runGroup{
		OkCode: okCode,
		Runner: runner,
	}
}

func (rg *runGroup) okCode(err error) bool {
	got := errCode(err)
	for _, want := range rg.OkCode {
		if got == want {
			return true
		}
	}
	return false
}

func (rg *runGroup) Output(args ...string) []byte {
	b, err := rg.Runner.output(args...)
	if rg.ErrAcc == nil && err != nil && !rg.okCode(err) {
		rg.ErrAcc = err
	}
	return b
}

func (rg *runGroup) Run(args ...string) {
	err := rg.Runner.run(args...)
	if rg.ErrAcc == nil && err != nil && !rg.okCode(err) {
		rg.ErrAcc = err
	}
}
