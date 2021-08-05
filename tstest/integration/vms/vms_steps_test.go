// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

package vms

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"inet.af/netaddr"
)

const timeout = 15 * time.Second

func retry(t *testing.T, fn func() error) {
	t.Helper()
	const tries = 3
	var err error
	for i := 0; i < tries; i++ {
		err = fn()
		if err != nil {
			t.Logf("%dth invocation failed, trying again: %v", i, err)
			time.Sleep(50 * time.Millisecond)
		}
		if err == nil {
			return
		}
	}
	t.Fatalf("tried %d times, got: %v", tries, err)
}

func (h *Harness) testPing(t *testing.T, ipAddr netaddr.IP, cli *ssh.Client) {
	var outp []byte
	var err error
	retry(t, func() error {
		sess := getSession(t, cli)

		outp, err = sess.CombinedOutput(fmt.Sprintf("tailscale ping -c 1 %s", ipAddr))
		return err
	})

	if !bytes.Contains(outp, []byte("pong")) {
		t.Log(string(outp))
		t.Fatal("no pong")
	}

	retry(t, func() error {
		sess := getSession(t, cli)

		// NOTE(Xe): the ping command is inconsistent across distros. Joy.
		pingCmd := fmt.Sprintf("sh -c 'ping -c 1 %[1]s || ping -6 -c 1 %[1]s || ping6 -c 1 %[1]s\n'", ipAddr)
		t.Logf("running %q", pingCmd)
		outp, err = sess.CombinedOutput(pingCmd)
		return err
	})

	if !bytes.Contains(outp, []byte("bytes")) {
		t.Log(string(outp))
		t.Fatalf("wanted output to contain %q, it did not", "bytes")
	}
}

func getSession(t *testing.T, cli *ssh.Client) *ssh.Session {
	sess, err := cli.NewSession()
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		sess.Close()
	})

	return sess
}

func (h *Harness) testOutgoingTCP(t *testing.T, ipAddr netaddr.IP, cli *ssh.Client) {
	const sendmsg = "this is a message that curl won't print"
	ctx, cancel := context.WithCancel(context.Background())
	s := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Logf("http connection from %s", r.RemoteAddr)
			cancel()
			fmt.Fprintln(w, sendmsg)
		}),
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("::", "0"))
	if err != nil {
		t.Fatalf("can't make HTTP server: %v", err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	go s.Serve(ln)

	// sess := getSession(t, cli)
	// sess.Stderr = logger.FuncWriter(t.Logf)
	// sess.Stdout = logger.FuncWriter(t.Logf)
	// sess.Run("ip route show table all")

	// sess = getSession(t, cli)
	// sess.Stderr = logger.FuncWriter(t.Logf)
	// sess.Stdout = logger.FuncWriter(t.Logf)
	// sess.Run("sysctl -a")

	var outp []byte
	retry(t, func() error {
		var err error
		sess := getSession(t, cli)
		v6Arg := ""
		if ipAddr.Is6() {
			v6Arg = "-6 -g"
		}
		cmd := fmt.Sprintf("curl -v %s -s -f http://%s\n", v6Arg, net.JoinHostPort(ipAddr.String(), port))
		t.Logf("running: %s", cmd)
		outp, err = sess.CombinedOutput(cmd)
		if err != nil {
			t.Log(string(outp))
		}
		return err
	})

	if msg := string(bytes.TrimSpace(outp)); !strings.Contains(msg, sendmsg) {
		t.Fatalf("wanted %q, got: %q", sendmsg, msg)
	}
	<-ctx.Done()
}
