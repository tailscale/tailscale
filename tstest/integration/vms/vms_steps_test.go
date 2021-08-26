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
	retry(t, func() error {
		sess := getSession(t, cli)
		cmd := fmt.Sprintf("tailscale ping --verbose %s", ipAddr)
		outp, err := sess.CombinedOutput(cmd)
		if err == nil && !bytes.Contains(outp, []byte("pong")) {
			err = fmt.Errorf("%s: no pong", cmd)
		}
		if err != nil {
			return fmt.Errorf("%s : %v, output: %s", cmd, err, outp)
		}
		t.Logf("%s", outp)
		return nil
	})

	retry(t, func() error {
		sess := getSession(t, cli)

		// NOTE(Xe): the ping command is inconsistent across distros. Joy.
		cmd := fmt.Sprintf("sh -c 'ping -c 1 %[1]s || ping -6 -c 1 %[1]s || ping6 -c 1 %[1]s\n'", ipAddr)
		t.Logf("running %q", cmd)
		outp, err := sess.CombinedOutput(cmd)
		if err == nil && !bytes.Contains(outp, []byte("bytes")) {
			err = fmt.Errorf("%s: wanted output to contain %q, it did not", cmd, "bytes")
		}
		if err != nil {
			err = fmt.Errorf("%s: %v, output: %s", cmd, err, outp)
		}
		return err
	})
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

	retry(t, func() error {
		var err error
		sess := getSession(t, cli)
		v6Arg := ""
		if ipAddr.Is6() {
			v6Arg = "-6 -g"
		}
		cmd := fmt.Sprintf("curl -v %s -s -f http://%s\n", v6Arg, net.JoinHostPort(ipAddr.String(), port))
		t.Logf("running: %s", cmd)
		outp, err := sess.CombinedOutput(cmd)
		if msg := string(bytes.TrimSpace(outp)); err == nil && !strings.Contains(msg, sendmsg) {
			err = fmt.Errorf("wanted %q, got: %q", sendmsg, msg)
		}
		if err != nil {
			err = fmt.Errorf("%v, output: %s", err, outp)
		}
		return err
	})

	<-ctx.Done()
}
