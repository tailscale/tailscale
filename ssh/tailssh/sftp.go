// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9

package tailssh

import (
	"io"
	"os"

	"github.com/pkg/sftp"
)

// stdRWC is an io.ReadWriteCloser over the process's stdin and stdout, for
// serving SFTP in a child process whose standard handles are connected to
// the SSH session.
type stdRWC struct{}

func (stdRWC) Read(p []byte) (n int, err error) {
	return os.Stdin.Read(p)
}

func (stdRWC) Write(b []byte) (n int, err error) {
	return os.Stdout.Write(b)
}

func (stdRWC) Close() error {
	os.Exit(0)
	return nil
}

// beSFTP is the entrypoint to the "tailscaled be-child sftp" subcommand.
// It serves SFTP in-process over stdin and stdout.
func beSFTP(args []string) error {
	return serveSFTP()
}

func serveSFTP() error {
	server, err := sftp.NewServer(stdRWC{})
	if err != nil {
		return err
	}
	// TODO(https://github.com/pkg/sftp/pull/554): Revert the check for io.EOF,
	// when sftp is patched to report clean termination.
	if err := server.Serve(); err != nil && err != io.EOF {
		return err
	}
	return nil
}
