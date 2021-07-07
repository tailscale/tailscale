// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux

package vms

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"tailscale.com/types/logger"
)

func mkSSHServer(t *testing.T, hostKey ssh.Signer, bindhost string) string {
	t.Helper()

	config := &ssh.ServerConfig{
		NoClientAuth: true,
		AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
			t.Logf("ssh server connection auth: %s, %s: %v", conn.RemoteAddr(), method, err)
		},
	}

	config.AddHostKey(hostKey)

	lis, err := net.Listen("tcp", net.JoinHostPort(bindhost, "0"))
	if err != nil {
		t.Fatalf("can't listen on anonymous port: %v", err)
	}

	t.Cleanup(func() {
		t.Logf("closing socket")
		lis.Close()
	})

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				t.Logf("unexpected SSH connection error: %v", err)
				return
			}

			go func() {
				sc, chanchan, reqchan, err := ssh.NewServerConn(conn, config)
				if err != nil {
					t.Logf("client can't register with ssh: %s: %v", conn.RemoteAddr(), err)
					return
				}
				defer sc.Close()

				go ssh.DiscardRequests(reqchan)

				newChannel := <-chanchan
				channel, requests, err := newChannel.Accept()
				if err != nil {
					t.Logf("can't accept channel from %s: %v", conn.RemoteAddr(), err)
					return
				}
				t.Logf("%s: %s", conn.RemoteAddr(), newChannel.ChannelType())

				go func(in <-chan *ssh.Request) {
					for req := range in {
						req.Reply(req.Type == "shell", nil)
					}
				}(requests)

				term := terminal.NewTerminal(channel, "> ")

				time.Sleep(time.Second)
				fmt.Fprintln(term, "connection established")
				channel.Close()
			}()
		}
	}()

	return lis.Addr().String()
}

func TestMkSSHServer(t *testing.T) {
	dir := t.TempDir()

	run(t, dir, "ssh-keygen", "-t", "ed25519", "-f", "machinekey", "-N", ``)

	privateKey, err := os.ReadFile(filepath.Join(dir, "machinekey"))
	if err != nil {
		t.Fatalf("can't read ssh private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		t.Fatalf("can't parse private key: %v", err)
	}

	addr := mkSSHServer(t, signer, "::1")
	t.Logf("connecting to %s", addr)
	host, port, _ := net.SplitHostPort(addr)

	// NOTE(Xe): I tried to use go's SSH library for this but it just wouldn't work.
	// The way my SSH server works is that it just spews stuff and kills the session
	// afterwards. This is apparently in violation of how SSH servers are supposed
	// to normally work, but the goal here is to get the text spewed back so it
	// doesn't really matter.
	cmd := exec.Command("ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "UserKnownHostsFile=/dev/null",
		host, "-p", port,
	)
	buf := bytes.NewBuffer(nil)
	cmd.Stdout = io.MultiWriter(buf, logger.FuncWriter(t.Logf))
	err = cmd.Run()
	if err != nil {
		if eerr, ok := err.(*exec.ExitError); ok {
			if eerr.ExitCode() != 255 {
				t.Fatalf("can't ssh into %s: %v", addr, err)
			}
		} else {
			t.Fatalf("can't ssh into %s: %v", addr, err)
		}
	}

	if !bytes.Contains(buf.Bytes(), []byte("connection established")) {
		t.Fatalf("wanted \"connection established\" from ssh server, got: %q", buf)
	}
}
