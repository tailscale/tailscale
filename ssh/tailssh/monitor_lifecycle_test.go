// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestMonitorExecCancellationAfterDispatch delays the exec reply until after
// cancellation. The session must retain the child handle and terminate it.
func TestMonitorExecCancellationAfterDispatch(t *testing.T) {
	client, peer := rpcTestPair(t)
	mc := &monitorClient{
		c:       client.c,
		rpc:     client,
		pending: make(map[int64]chan *rpcResult),
		done:    make(chan struct{}),
	}
	go mc.readLoop()
	t.Cleanup(func() {
		client.c.Close()
		<-mc.done
	})
	c := &conn{srv: &server{logf: t.Logf}}
	c.monitor.mon = mc
	mc.SetExitCallback(c.monitor.exits.dispatchExit)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ss := &sshSession{conn: c, ctx: ctx, logf: t.Logf}
	f, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	launched := make(chan error, 1)
	cmd := exec.Command("/unused/incubator")
	stdio := []*os.File{f, f, f}
	go func() {
		launched <- ss.launchViaMonitor(cmd, nil, stdio, false)
	}()
	frame, fds, err := peer.readFrame()
	closeFds(fds)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Op != opExec {
		t.Fatalf("op=%s; want exec", frame.Op)
	}
	cancel()
	child := monitorProcess{PID: 42, ID: frame.ID}
	if err := peer.writeFrame(rpcExecReply(frame.ID, child.PID)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-launched:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exec did not return its reply")
	}
	if ss.monChild != child {
		t.Fatalf("child=%v; want %v", ss.monChild, child)
	}

	hungup := make(chan bool, 1)
	go func() { hungup <- ss.hangupMonitorProcess() }()
	frame, fds, err = peer.readFrame()
	closeFds(fds)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Op != opSignal || frame.Pid != child.PID || frame.ChildID != child.ID || frame.Sig != "SIGHUP" {
		t.Fatalf("hangup frame=%+v", frame)
	}
	if err := peer.writeFrame(rpcOKReply(frame.ID, opSignal)); err != nil {
		t.Fatal(err)
	}
	if !<-hungup {
		t.Fatal("canceled session lost its monitor child")
	}
	if err := peer.writeFrame(rpcExitNotify(child, 129)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ss.monExit.done:
	case <-time.After(5 * time.Second):
		t.Fatal("exit notification not delivered")
	}
	// Escalation must neither consume the result nor send another signal.
	ss.escalateMonitorProcess(mc)
	for range 2 {
		code, ok, err := ss.waitMonitorProcess()
		if code != 129 || !ok || err != nil {
			t.Fatalf("wait=(%d,%v,%v)", code, ok, err)
		}
	}
}

// A locally rejected request must not kill other sessions on the connection.
func TestMonitorValidationFailureKeepsChannel(t *testing.T) {
	for _, tt := range []struct {
		name    string
		frame   rpcFrame
		nfds    int
		wantErr string
	}{
		{"line_cap", rpcExecReq(0, []string{strings.Repeat("x", rpcMaxLine)}, nil, "", false, false, 1), 1, "line cap"},
		{"fd_count", rpcExecReq(0, []string{"/bin/true"}, nil, "", false, false, rpcMaxFds+1), rpcMaxFds + 1, "cannot carry"},
		{"op_fd_count", rpcPingReq(0), 1, "cannot carry"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mc := startTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))
			exits := collectExits(mc)
			child, err := mc.Exec(mustCtx(t), []string{"/bin/sleep", "30"}, nil, "/", false, nil)
			if err != nil {
				t.Fatal(err)
			}
			fds := make([]int, tt.nfds)
			for i := range fds {
				fds[i] = devNullFd(t)
			}
			_, _, err = mc.call(mustCtx(t), tt.frame, fds...)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("call error = %v; want %q", err, tt.wantErr)
			}
			mc.mu.Lock()
			npending := len(mc.pending)
			mc.mu.Unlock()
			if npending != 0 {
				t.Fatalf("pending requests = %d; want 0", npending)
			}
			if err := mc.Ping(mustCtx(t)); err != nil {
				t.Fatalf("ping after validation failure: %v", err)
			}
			if err := mc.Signal(mustCtx(t), child, "SIGTERM"); err != nil {
				t.Fatal(err)
			}
			note := waitExitNote(t, exits, 5*time.Second)
			if note.pid != child || note.code != 143 {
				t.Fatalf("exit=%+v; want child=%+v code=143", note, child)
			}
		})
	}
}

func TestMonitorWriteFailureClosesChannel(t *testing.T) {
	for _, partial := range []bool{false, true} {
		name := "closed_write"
		if partial {
			name = "partial_write"
		}
		t.Run(name, func(t *testing.T) {
			client, peer := rpcTestPair(t)
			mc := &monitorClient{
				c:       client.c,
				rpc:     client,
				pending: make(map[int64]chan *rpcResult),
				done:    make(chan struct{}),
			}
			go mc.readLoop()
			t.Cleanup(func() {
				client.c.Close()
				<-mc.done
			})
			frame := rpcPingReq(0)
			if partial {
				if err := client.c.SetWriteBuffer(1024); err != nil {
					t.Fatal(err)
				}
				client.writeTimeout = 100 * time.Millisecond
				frame = rpcExecReq(0, []string{strings.Repeat("x", 100<<10)}, nil, "", false, false, 0)
			} else if err := client.c.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if _, _, err := mc.call(mustCtx(t), frame); err == nil {
				t.Fatal("write succeeded unexpectedly")
			}
			select {
			case <-mc.done:
			case <-time.After(5 * time.Second):
				t.Fatal("write failure did not close the channel")
			}
			if err := peer.c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			// Drain any partial frame and verify EOF triggers peer teardown.
			n, err := io.Copy(io.Discard, peer.c)
			if err != nil {
				t.Fatalf("drain peer: %v; want EOF", err)
			}
			if partial && (n == 0 || n >= 100<<10) {
				t.Fatalf("wrote %d bytes; want a partial frame", n)
			}
		})
	}
}

func TestMonitorReadFailureClosesChannel(t *testing.T) {
	client, peer := rpcTestPair(t)
	mc := &monitorClient{
		c:       client.c,
		rpc:     client,
		pending: make(map[int64]chan *rpcResult),
		done:    make(chan struct{}),
	}
	go mc.readLoop()
	t.Cleanup(func() {
		client.c.Close()
		<-mc.done
	})
	if _, err := peer.c.Write([]byte("invalid JSON\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-mc.done:
	case <-time.After(5 * time.Second):
		t.Fatal("read loop did not reject the invalid frame")
	}
	if err := peer.c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := peer.c.Read(b[:]); err != io.EOF {
		t.Fatalf("peer read = %v; want EOF to trigger monitor teardown", err)
	}
}

func TestMonitorRejectsStaleChildHandle(t *testing.T) {
	mc := startTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))
	exits := collectExits(mc)
	child, err := mc.Exec(mustCtx(t), []string{"/bin/sleep", "30"}, nil, "/", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	stale := child
	stale.ID++
	if err := mc.Signal(mustCtx(t), stale, "SIGKILL"); err == nil {
		t.Fatal("signal accepted a mismatched child generation")
	}
	if err := mc.Signal(mustCtx(t), child, "SIGTERM"); err != nil {
		t.Fatal(err)
	}
	note := waitExitNote(t, exits, 5*time.Second)
	if note.pid != child || note.code != 143 {
		t.Fatalf("exit=%+v; want child=%+v code=143", note, child)
	}
}

func TestIncubatorRejectsIdentityAliases(t *testing.T) {
	m := &monitor{
		args: monitorArgs{
			uid:       1000,
			gid:       1000,
			gids:      []uint32{1000},
			localUser: "ubuntu",
		},
	}
	for _, alias := range [][]string{
		{"-uid=0"},
		{"--uid", "0"},
		{"-gid=0"},
		{"--gid", "0"},
		{"-groups=0"},
		{"--groups", "0"},
		{"-local-user=root"},
		{"--local-user", "root"},
	} {
		argv := append([]string{
			"/tailscaled", "be-child", "ssh",
			"--uid=1",
			"--gid=1",
			"--groups=1",
			"--local-user=alice",
		}, alias...)
		if _, err := m.incubatorArgv(argv); err == nil {
			t.Errorf("accepted identity alias %q", alias)
		}
	}
}
