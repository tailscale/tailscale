// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package chirp

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeBIRD struct {
	net.Listener
	protocolsEnabled map[string]bool
	sock             string
}

func newFakeBIRD(t *testing.T, protocols ...string) *fakeBIRD {
	sock := filepath.Join(t.TempDir(), "sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	pe := make(map[string]bool)
	for _, p := range protocols {
		pe[p] = false
	}
	return &fakeBIRD{
		Listener:         ln,
		protocolsEnabled: pe,
		sock:             sock,
	}
}

func (fb *fakeBIRD) listen() error {
	for {
		c, err := fb.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go fb.handle(c)
	}
}

func (fb *fakeBIRD) handle(c net.Conn) {
	fmt.Fprintln(c, "0001 BIRD 2.0.8 ready.")
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		cmd := sc.Text()
		args := strings.Split(cmd, " ")
		switch args[0] {
		case "enable":
			en, ok := fb.protocolsEnabled[args[1]]
			if !ok {
				fmt.Fprintln(c, "9001 syntax error, unexpected CF_SYM_UNDEFINED, expecting CF_SYM_KNOWN or TEXT or ALL")
			} else if en {
				fmt.Fprintf(c, "0010-%s: already enabled\n", args[1])
			} else {
				fmt.Fprintf(c, "0011-%s: enabled\n", args[1])
			}
			fmt.Fprintln(c, "0000 ")
			fb.protocolsEnabled[args[1]] = true
		case "disable":
			en, ok := fb.protocolsEnabled[args[1]]
			if !ok {
				fmt.Fprintln(c, "9001 syntax error, unexpected CF_SYM_UNDEFINED, expecting CF_SYM_KNOWN or TEXT or ALL")
			} else if !en {
				fmt.Fprintf(c, "0008-%s: already disabled\n", args[1])
			} else {
				fmt.Fprintf(c, "0009-%s: disabled\n", args[1])
			}
			fmt.Fprintln(c, "0000 ")
			fb.protocolsEnabled[args[1]] = false
		}
	}
}

func TestChirp(t *testing.T) {
	fb := newFakeBIRD(t, "tailscale")
	defer fb.Close()
	go fb.listen()
	c, err := New(fb.sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.EnableProtocol("tailscale"); err != nil {
		t.Fatal(err)
	}
	if err := c.EnableProtocol("tailscale"); err != nil {
		t.Fatal(err)
	}
	if err := c.DisableProtocol("tailscale"); err != nil {
		t.Fatal(err)
	}
	if err := c.DisableProtocol("tailscale"); err != nil {
		t.Fatal(err)
	}
	if err := c.EnableProtocol("rando"); err == nil {
		t.Fatalf("enabling %q succeeded", "rando")
	}
	if err := c.DisableProtocol("rando"); err == nil {
		t.Fatalf("disabling %q succeeded", "rando")
	}
}

type hangingListener struct {
	net.Listener
	t    *testing.T
	done chan struct{}
	wg   sync.WaitGroup
	sock string
}

func newHangingListener(t *testing.T) *hangingListener {
	sock := filepath.Join(t.TempDir(), "sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	return &hangingListener{
		Listener: ln,
		t:        t,
		done:     make(chan struct{}),
		sock:     sock,
	}
}

func (hl *hangingListener) Stop() {
	hl.Close()
	close(hl.done)
	hl.wg.Wait()
}

func (hl *hangingListener) listen() error {
	for {
		c, err := hl.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		hl.wg.Add(1)
		go hl.handle(c)
	}
}

func (hl *hangingListener) handle(c net.Conn) {
	defer hl.wg.Done()

	// Write our fake first line of response so that we get into the read loop
	fmt.Fprintln(c, "0001 BIRD 2.0.8 ready.")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			hl.t.Logf("connection still hanging")
		case <-hl.done:
			return
		}
	}
}

func TestChirpTimeout(t *testing.T) {
	fb := newHangingListener(t)
	defer fb.Stop()
	go fb.listen()

	c, err := newWithTimeout(fb.sock, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	err = c.EnableProtocol("tailscale")
	if err == nil {
		t.Fatal("got err=nil, want timeout")
	}
	if !os.IsTimeout(err) {
		t.Fatalf("got err=%v, want os.IsTimeout(err)=true", err)
	}
}
