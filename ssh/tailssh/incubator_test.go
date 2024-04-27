// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build integrationtest
// +build integrationtest

package tailssh

import (
	"bufio"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestBeIncubator runs an integration test of the beIncubator function. It
// expects an execution environment that meets the following requirements:
//
// - OS is one of MacOS, Linux, FreeBSD or OpenBSD
// - User "testuser" exists
// - "theuser" is in groups "groupone" and "grouptwo"
func TestIntegrationBeIncubator(t *testing.T) {
	runningInTest = true
	t.Cleanup(func() {
		runningInTest = false
	})

	testuser, err := user.Lookup("testuser")
	if err != nil {
		t.Fatal(err)
	}
	groupone, err := user.LookupGroup("groupone")
	if err != nil {
		t.Fatal(err)
	}
	grouptwo, err := user.LookupGroup("grouptwo")
	if err != nil {
		t.Fatal(err)
	}

	runCmd := func(cmd string) string {
		errCh := make(chan error, 1)
		defer func() {
			select {
			case err := <-errCh:
				if err != nil {
					t.Fatal(err)
				}
			}
		}()

		args := []string{
			"--uid", testuser.Uid,
			"--gid", testuser.Gid,
			"--groups", groupone.Gid + "," + grouptwo.Gid,
			"--local-user", "testuser",
			"--remote-user", "remoteuser",
			"--remote-ip", "192.168.1.180",
			"--cmd", cmd,
		}

		log.Printf("Testing with args %+v", args)

		stdinReader, stdin := io.Pipe()
		stdoutReader, stdoutWriter := io.Pipe()
		stderrReader, stderrWriter := io.Pipe()
		defer stdin.Close()
		defer stdoutReader.Close()
		defer stderrReader.Close()

		go func() {
			errCh <- doBeIncubator(args, os.Environ(), stdinReader, stdoutWriter, stderrWriter)
		}()

		stdout := bufio.NewReader(stdoutReader)
		go io.Copy(os.Stderr, stderrReader)
		result, err := stdout.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(result)
	}

	gotId := runCmd("id")
	if !strings.Contains(gotId, "testuserd") {
		t.Logf("id output %q missing testuser", gotId)
	}
	if !strings.Contains(gotId, "groupone") {
		t.Logf("id output %q missing groupone", gotId)
	}
	if !strings.Contains(gotId, "grouptwo") {
		t.Logf("id output %q missing grouptwo", gotId)
	}

	_, err = exec.LookPath("su")
	if err == nil {
		// If su command is present, make sure that pwd without TTY shows the
		// correct directory.
		gotPwd := runCmd("pwd")
		wantPwd := "/home/testuserd"
		if runtime.GOOS == "darwin" {
			wantPwd = "/Users/testuser"
		}
		if diff := cmp.Diff(gotPwd, wantPwd); diff != "" {
			t.Fatalf("unexpected pwd output (-got +want):\n%s", diff)
		}
	}
}
