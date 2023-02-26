// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux
// +build linux

package pidlisten

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

var flagDial = flag.String("dial", "", "if set, dials the given addr and reads until close")

func TestMain(m *testing.M) {
	flag.Parse()
	if *flagDial != "" {
		conn, err := net.DialTimeout("tcp", *flagDial, 5*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		b, err := io.ReadAll(conn)
		fmt.Fprintf(os.Stderr, "%s", b)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestPIDLocal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	ok, err := checkPIDLocal(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Errorf("checkPIDLocal=false, want true")
	}
}

func testExternalProcess(t *testing.T, ln net.Listener) string {
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				panic(err)
			}
			fmt.Fprintf(c, "hello\n")
			c.Close()
		}
	}()

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command(exe, "-dial="+ln.Addr().String()).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestExternalDialWorks(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	out := testExternalProcess(t, ln)
	if out != "hello\n" {
		t.Errorf("out=%q, want hello", out)
	}
}

func TestPIDExternal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ln = NewPIDListener(ln)
	out := testExternalProcess(t, ln)

	if len(out) != 0 {
		t.Errorf("unexpected socket output: %q", out)
	}
}
