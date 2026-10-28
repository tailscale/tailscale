// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package tailssh

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gliderssh "github.com/tailscale/gliderssh"
	gossh "golang.org/x/crypto/ssh"
)

// TestNotifySocketDoesNotReachChildren runs a real session through a
// real monitor with NOTIFY_SOCKET set. The session child and the
// monitor must not hold the variable. Nothing may send a notification
// to the socket. The socket check is best effort, because it only
// observes the daemon-side loginctl probes, which run on Debian-family
// hosts. Hostinfo's TestLogindProbesDropSystemdServiceEnv pins the
// probe's own environment.
func TestNotifySocketDoesNotReachChildren(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "notify")
	ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sockPath, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	notifications := make(chan string, 16)
	go func() {
		for {
			b := make([]byte, 4096)
			n, rerr := ln.Read(b)
			if rerr != nil {
				return
			}
			select {
			case notifications <- string(b[:n]):
			default:
			}
		}
	}()

	// The daemon-side environment, as under a Type=notify systemd unit.
	t.Setenv("NOTIFY_SOCKET", sockPath)

	connCh := make(chan *conn, 1)
	addr := newMonitorSessionServer(t, func(c *conn, s gliderssh.Session) {
		select {
		case connCh <- c:
		default:
		}
		c.newSSHSession(s).run()
	})

	cl, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	s, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var out sessTestBuffer
	s.Stdout = &out
	s.Stderr = &out
	if err := s.Run("echo ENV-BEGIN; env; echo ENV-END"); err != nil {
		t.Logf("session command: %v", err)
	}

	// The session child must not see the notify socket in its
	// environment.
	envOut := out.String()
	if !strings.Contains(envOut, "ENV-BEGIN") {
		t.Fatalf("no session output; got %q", envOut)
	}
	if strings.Contains(envOut, "NOTIFY_SOCKET=") {
		t.Errorf("session child environment contains NOTIFY_SOCKET:\n%s", envOut)
	}

	// The monitor process must not hold the daemon's systemd
	// service-instance variables either.
	var c *conn
	select {
	case c = <-connCh:
	case <-time.After(10 * time.Second):
		t.Fatal("session never started")
	}
	var mc *monitorClient
	deadline := time.Now().Add(10 * time.Second)
	for mc == nil {
		mc = c.connMonitorIfAny()
		if mc == nil {
			if time.Now().After(deadline) {
				t.Fatal("connection monitor never spawned")
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	monEnv, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", mc.Pid()))
	if err != nil {
		t.Fatalf("reading monitor (pid %d) environment: %v", mc.Pid(), err)
	}
	for _, kv := range strings.Split(string(monEnv), "\x00") {
		if strings.HasPrefix(kv, "NOTIFY_SOCKET=") {
			t.Errorf("ssh-monitor child environment contains %q", kv)
		}
	}

	// No child may send notifications to the notify socket.
	select {
	case n := <-notifications:
		t.Errorf("notification sent by a child process: %q", n)
	case <-time.After(2 * time.Second):
	}
}
