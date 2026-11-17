// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package tailssh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/net/memnet"
	"tailscale.com/tailcfg"
	testssh "tailscale.com/tempfork/sshtest/ssh"
	"tailscale.com/tstest"
)

// TestFwdFullStackLocalUnixPayloadCredentials checks the credentials on
// payload writes, not just the peer credentials established at dial time.
func TestFwdFullStackLocalUnixPayloadCredentials(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("cross-UID payload credentials require a root-run server; same-UID forwarding is tested by TestFwdFullStackLocalUnix")
	}
	lu := fwdTestIdentity(t)
	boundUID, err := strconv.Atoi(lu.Uid)
	if err != nil {
		t.Fatal(err)
	}
	boundGID, err := strconv.Atoi(lu.Gid)
	if err != nil {
		t.Fatal(err)
	}
	if boundUID == os.Getuid() {
		t.Fatal("test identity must differ from server identity")
	}

	exe := makeExecutableReachable(t)
	t.Setenv("TS_TEST_SSH_FWD_PREFIX", strings.Join(testFwdPrefix, " "))
	tstest.Replace(t, &monitorSpawnPrefix, testMonitorPrefix)

	// A 0700 directory owned by the mapped user and a 0600 socket keep
	// this canary private to the mapped user (and the root test process).
	// Use /tmp explicitly: the full-stack forwarding allowlist rejects
	// arbitrary TMPDIR values.
	dir, err := os.MkdirTemp("/tmp", "tailssh-payload-creds-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chown(dir, boundUID, boundGID); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(dir, "payload-creds.sock")
	// Arm SO_PASSCRED before accept so credentials on the first payload
	// are preserved even if the sender writes before the server receives.
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
		}); err != nil {
			return err
		}
		return sockErr
	}}
	ln, err := lc.Listen(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	if err := os.Chown(socketPath, boundUID, boundGID); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		t.Fatal(err)
	}
	marker := []byte("ssh-unix-payload-marker")
	type result struct {
		uid int
		err error
	}
	received := make(chan result, 2)
	go func() {
		for range 2 {
			sc, err := ln.Accept()
			if err != nil {
				received <- result{err: err}
				return
			}
			func() {
				defer sc.Close()
				uid, err := recvFwdPayloadCredentials(sc.(*net.UnixConn), marker)
				if err == nil {
					_, err = sc.Write(marker)
				}
				received <- result{uid: uid, err: err}
			}()
		}
	}()

	// The direct connection is a same-user control for SO_PASSCRED and
	// recvmsg on this listener, independent of SSH forwarding.
	direct, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := direct.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := direct.Write(marker); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(marker))
	if _, err := io.ReadFull(direct, got); err != nil {
		t.Fatal(err)
	}
	direct.Close()
	if !bytes.Equal(got, marker) {
		t.Fatalf("direct echo = %q; want %q", got, marker)
	}
	select {
	case r := <-received:
		if r.err != nil || r.uid != os.Getuid() {
			t.Fatalf("direct payload credentials = uid %d, err %v; want uid %d", r.uid, r.err, os.Getuid())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("direct service receive timed out")
	}

	rule := &tailcfg.SSHRule{
		SSHUsers: map[string]string{"alice": lu.Username},
		Action:   &tailcfg.SSHAction{Accept: true, AllowLocalPortForwarding: true},
		Principals: []*tailcfg.SSHPrincipal{
			{Any: true},
		},
	}
	s := &server{
		logf:           t.Logf,
		tailscaledPath: exe,
		lb: &localState{
			sshEnabled:   true,
			varRoot:      t.TempDir(),
			matchingRule: rule,
		},
	}
	src, dst := netip.MustParseAddrPort("100.100.100.101:2231"), netip.MustParseAddrPort("100.100.100.102:22")
	clientConn, serverConn := memnet.NewTCPConn(src, dst, 1024)
	if err := clientConn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		cl, chans, reqs, err := testssh.NewClientConn(clientConn, clientConn.RemoteAddr().String(), &testssh.ClientConfig{
			User:            "alice",
			HostKeyCallback: testssh.InsecureIgnoreHostKey(),
			Timeout:         15 * time.Second,
		})
		if err != nil {
			t.Errorf("client handshake: %v", err)
			return
		}
		client := testssh.NewClient(cl, chans, reqs)
		defer client.Close()
		uc, err := client.Dial("unix", socketPath)
		if err != nil {
			t.Errorf("client -L dial: %v", err)
			return
		}
		defer uc.Close()
		if _, err := uc.Write(marker); err != nil {
			t.Errorf("forwarded write: %v", err)
			return
		}
		got := make([]byte, len(marker))
		if _, err := io.ReadFull(uc, got); err != nil {
			t.Errorf("forwarded read: %v", err)
			return
		}
		if !bytes.Equal(got, marker) {
			t.Errorf("forwarded echo = %q; want %q", got, marker)
		}
	})
	if err := s.HandleSSHConn(serverConn); err != nil {
		t.Errorf("HandleSSHConn: %v", err)
	}
	wg.Wait()
	select {
	case r := <-received:
		if r.err != nil {
			t.Fatalf("forwarded service receive: %v", r.err)
		}
		if r.uid != boundUID {
			t.Errorf("forwarded payload SCM_CREDENTIALS uid = %d; want mapped uid %d (server uid %d)", r.uid, boundUID, os.Getuid())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("forwarded service receive timed out")
	}
}

// recvFwdPayloadCredentials receives the first payload bytes with recvmsg
// to inspect SCM_CREDENTIALS enabled on the listener before accept.
func recvFwdPayloadCredentials(sc *net.UnixConn, marker []byte) (int, error) {
	f, err := sc.File()
	if err != nil {
		return 0, err
	}
	defer f.Close()
	fd := int(f.Fd())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 10}); err != nil {
		return 0, err
	}
	got := make([]byte, len(marker))
	oob := make([]byte, unix.CmsgSpace(unix.SizeofUcred))
	n, oobn, flags, _, err := unix.Recvmsg(fd, got, oob, 0)
	if err != nil {
		return 0, err
	}
	if n == 0 || flags&unix.MSG_CTRUNC != 0 {
		return 0, fmt.Errorf("recvmsg: n=%d flags=%d", n, flags)
	}
	if _, err := io.ReadFull(sc, got[n:]); err != nil {
		return 0, err
	}
	if !bytes.Equal(got, marker) {
		return 0, fmt.Errorf("payload = %q; want %q", got, marker)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, err
	}
	for _, msg := range msgs {
		if msg.Header.Level == unix.SOL_SOCKET && msg.Header.Type == unix.SCM_CREDENTIALS {
			cred, err := unix.ParseUnixCredentials(&msg)
			if err != nil {
				return 0, err
			}
			return int(cred.Uid), nil
		}
	}
	return 0, fmt.Errorf("recvmsg: no SCM_CREDENTIALS in %d control messages", len(msgs))
}
