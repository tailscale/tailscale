// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package tailssh

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os/exec"
	"syscall"
	"testing"

	"github.com/creack/pty"
	"tailscale.com/types/logger"
)

// TestKillOnContextDoneClosesPTYMaster verifies the fix for #21150: when the
// client connection drops, the session teardown must close the pty master
// (the session's stdin writer) so the kernel delivers SIGHUP to the slave's
// foreground process group - reaping login shells that outlived their
// login/su helper. Reading the slave after the last master closes yields
// EIO on Linux and EOF on darwin.
func TestKillOnContextDoneClosesPTYMaster(t *testing.T) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Skipf("pty.Open: %v", err)
	}
	defer tty.Close()

	ctx, cancel := context.WithCancelCause(context.Background())
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skipf("starting sleep: %v", err)
	}
	defer cmd.Process.Kill()

	ss := &sshSession{
		ctx:         ctx,
		cancelCtx:   cancel,
		logf:        logger.Discard,
		conn:        &conn{info: &sshConnInfo{src: netip.MustParseAddrPort("100.64.0.1:12345")}},
		cmd:         cmd,
		wrStdin:     ptmx,
		exitHandled: make(chan struct{}),
	}

	cancel(errors.New("client disconnected"))
	ss.killProcessOnContextDone()

	// Idempotency: the stdin copier goroutine also closes on its way out;
	// this must be safe (a double Close on an *os.File risks closing an
	// unrelated reused fd).
	ss.closeStdin()

	// With the last master fd closed, a read on the slave must fail
	// (EIO on Linux, EOF on darwin) instead of blocking forever.
	buf := make([]byte, 8)
	_, err = tty.Read(buf)
	if err == nil {
		t.Fatal("read from pty slave succeeded after master close; want EIO or EOF")
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.EIO) {
		t.Fatalf("read from pty slave: got %v, want EIO or EOF", err)
	}
}
