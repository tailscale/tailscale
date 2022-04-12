// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

// Package kmod provides a simple API to attempt to ensure that a kernel
// module is loaded in a wide variety of environments, and otherwise
// report descriptive loggable error strings.
// This package does not have extensive unit testing, as the broader set
// of challenges associated with the package come from a wide variety of
// distribution and linux version differences that are problematic to
// mock/stub/emulate, including syscall boundary behaviors. The program
// `ensuremod` is kept nearby the source that provides a method for
// integration testing.
package kmod

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"go4.org/mem"
	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"
	"pault.ag/go/modprobe"
	"tailscale.com/util/lineread"
	"tailscale.com/util/multierr"
)

// hasKernelModule attempts to find a kernel module by name using procfs and
// sysfs. If the module is found to be loaded, true is returned, in all other
// cases false is returned, regardless of errors or a missing module.
func hasKernelModule(name string) (bool, error) {
	if _, err := os.Stat(filepath.Join("/sys/module", name)); err == nil {
		return true, nil
	}

	prefix := mem.S(name + " ")
	stopFound := errors.New("")

	err := lineread.File("/proc/modules", func(line []byte) error {
		if mem.HasPrefix(mem.B(line), prefix) {
			return stopFound
		}
		return nil
	})
	if err == stopFound {
		return true, nil
	}
	if err != nil {
		err = fmt.Errorf("module %s not found in /sys/module or /proc/modules: %w", name, err)
	}
	return false, err
}

// canInstallModule attempts to determine if the current process has sufficient
// privilege to install modules.  If the capabilities API can be queried without
// error, then the result depends on the SYS_MODULE effective capability,
// otherwise returns true only if the current process is running as root. A
// result of true implies that it may be worth trying to install a module, not
// that doing so will work.
func canInstallModule() (bool, error) {
	caps, err := cap.GetPID(0) // 0 = current process
	if err == nil {
		// errors from GetFlag are either due to the receiver being
		// uninitialized, or the kernel gave junk results, both of which aren't
		// very meaningful out of context to a user, so this error is mostly
		// ignored.
		b, err := caps.GetFlag(cap.Effective, cap.SYS_MODULE)
		if err == nil {
			return b, nil
		}
	}

	// could not determine a well known result from capabilities, make an
	// assumption based on uid.
	if os.Getuid() == 0 {
		return true, nil
	}
	return false, fmt.Errorf("not running as root, and unable to check kernel module capabilities")
}

// firstExecutable checks paths for a path that exists and is executable by the current user.
func firstExecutable(paths ...string) string {
	for _, path := range paths {
		if unix.Access(path, unix.X_OK) == nil {
			return path
		}
	}
	return ""
}

// runModprobe runs `modprobePath name` and reports summary error output on error.
func runModprobe(name, modprobePath string) error {
	cmd := exec.Command(modprobePath, name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("%q failed: %w; %s", fmt.Sprintf("%s %s", modprobePath, name), err, bytes.TrimSpace(out))
	}
	return err
}

// tryInstallModule attempts to find a modprobe binary to run either in
// well-known paths, or in $PATH, and runs it. If it can not find a modprobe to
// run, it instead falls back to a syscall interface to attempt to install a
// module.
func tryInstallModule(name string) error {
	path := firstExecutable("/usr/sbin/modprobe", "/sbin/modprobe")
	if path != "" {
		return runModprobe(name, path)
	}
	path, err := exec.LookPath("modprobe")
	if err == nil {
		return runModprobe(name, path)
	}

	err = modprobe.Load(name, "")
	if err != nil {
		err = fmt.Errorf("unable to find modprobe(1), and load of module %s failed with: %w", name, err)
	}
	return err
}

// EnsureModule attempts to ensure that the given module is installed, returning
// true only if it has been found or successfully installed, otherwise false is
// returned along with a list of informational errors about probe attempts.
func EnsureModule(name string) (bool, error) {
	has, hasErr := hasKernelModule(name)
	if has {
		return has, nil
	}
	var errors []error
	if hasErr != nil {
		errors = append(errors, hasErr)
	}

	can, canErr := canInstallModule()
	if can && canErr != nil {
		errors = append(errors, canErr)
	}
	if !can {
		if canErr == nil {
			errors = append(errors, fmt.Errorf("module %q not found, and current user can not install modules", name))
		}
	}

	if can {
		if err := tryInstallModule(name); err == nil {
			return true, nil
		} else {
			errors = append(errors, err)
		}
	}

	return false, multierr.New(errors...)
}
