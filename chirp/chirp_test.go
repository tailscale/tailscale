// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package chirp

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

type fakeBIRD struct {
	net.Listener
	protocolsEnabled map[string]bool
	sock             string
}

func newFakeBIRD(t *testing.T, protocols ...string) *fakeBIRD {
	sock := filepath.Join(t.TempDir(), "sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	pe := make(map[string]bool)
	for _, p := range protocols {
		pe[p] = false
	}
	return &fakeBIRD{
		Listener:         l,
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
		t.Fatalf("enabling %q succeded", "rando")
	}
	if err := c.DisableProtocol("rando"); err == nil {
		t.Fatalf("disabling %q succeded", "rando")
	}
}
