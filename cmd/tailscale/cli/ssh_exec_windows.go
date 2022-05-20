// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"errors"
	"os"
	"os/exec"
)

func execSSH(ssh string, argv []string) error {
	// Don't use syscall.Exec on Windows, it's not fully implemented.
	cmd := exec.Command(ssh, argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	var ee *exec.ExitError
	err := cmd.Run()
	if errors.As(err, &ee) {
		os.Exit(ee.ExitCode())
	}
	return err
}
