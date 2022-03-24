// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"syscall"

	"github.com/alessio/shellescape"
	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/envknob"
)

var sshCmd = &ffcli.Command{
	Name:       "ssh",
	ShortUsage: "ssh [user@]<host> [args...]",
	ShortHelp:  "SSH to a Tailscale machine",
	Exec:       runSSH,
}

func runSSH(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ssh [user@]<host>")
	}
	arg, argRest := args[0], args[1:]
	username, host, ok := strings.Cut(arg, "@")
	if !ok {
		host = arg
		lu, err := user.Current()
		if err != nil {
			return nil
		}
		username = lu.Username
	}
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		// TODO(bradfitz): use Go's crypto/ssh client instead
		// of failing. But for now:
		return fmt.Errorf("no system 'ssh' command found: %w", err)
	}
	tailscaleBin, err := os.Executable()
	if err != nil {
		return err
	}
	argv := append([]string{
		ssh,

		"-o", fmt.Sprintf("ProxyCommand %s --socket=%s nc %%h %%p",
			shellescape.Quote(tailscaleBin),
			shellescape.Quote(rootArgs.socket),
		),

		// Explicitly rebuild the user@host argument rather than
		// passing it through.  In general, the use of OpenSSH's ssh
		// binary is a crutch for now.  We don't want to be
		// Hyrum-locked into passing through all OpenSSH flags to the
		// OpenSSH client forever. We try to make our flags and args
		// be compatible, but only a subset. The "tailscale ssh"
		// command should be a simple and portable one. If they want
		// to use a different one, we'll later be making stock ssh
		// work well by default too. (doing things like automatically
		// setting known_hosts, etc)
		username + "@" + host,
	}, argRest...)

	if runtime.GOOS == "windows" {
		// Don't use syscall.Exec on Windows.
		cmd := exec.Command(ssh, argv[1:]...)
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		var ee *exec.ExitError
		err := cmd.Run()
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		return err
	}

	if envknob.Bool("TS_DEBUG_SSH_EXEC") {
		log.Printf("Running: %q, %q ...", ssh, argv)
	}
	if err := syscall.Exec(ssh, argv, os.Environ()); err != nil {
		return err
	}
	return errors.New("unreachable")
}
