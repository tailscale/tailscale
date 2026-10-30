// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios)

package tailssh

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/tstest"
)

func TestMonitorTerminationRPCFailureFailsClosed(t *testing.T) {
	for _, mode := range []string{"kill-all", "terminate", "unrequested-eof"} {
		t.Run(mode, func(t *testing.T) {
			mc := startTestMonitor(t, os.Getuid(), os.Getgid(), testGroups(t))
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer null.Close()
			child, err := mc.Exec(mustCtx(t), []string{"/bin/sh", "-c", "trap '' HUP; echo ready; while :; do sleep 1; done"}, nil, "/", false, nil, null, w, null)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Kill(-child.PID, unix.SIGKILL) })
			w.Close()
			r.SetReadDeadline(time.Now().Add(5 * time.Second))
			if line, err := bufio.NewReader(r).ReadString('\n'); err != nil || line != "ready\n" {
				t.Fatalf("ready = %q, %v", line, err)
			}
			if mode == "unrequested-eof" {
				mc.c.Close()
			} else {
				// Fail the next termination request's write.
				if err := mc.c.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if mode == "kill-all" {
					err = mc.KillAll(ctx)
				} else {
					err = mc.Terminate(ctx, child, hangupEscalation)
				}
				if err == nil {
					t.Fatal("mandate unexpectedly succeeded on broken RPC")
				}
			}
			if err := mc.Close(); err != nil {
				t.Fatal(err)
			}
			if err := tstest.WaitFor(5*time.Second, func() error {
				if !pidGone(child.PID) {
					return fmt.Errorf("child %d survived failed mandate", child.PID)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
