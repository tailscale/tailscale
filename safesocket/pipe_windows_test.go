// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package safesocket

import (
	"fmt"
	"testing"

	"tailscale.com/util/winutil"
)

func init() {
	// downgradeSDDL is a test helper that downgrades the windowsSDDL variable if
	// the currently running user does not have sufficient priviliges to set the
	// SDDL.
	downgradeSDDL = func() (cleanup func()) {
		// The current default descriptor can not be set by mere mortal users,
		// so we need to undo that for executing tests as a regular user.
		if !winutil.IsCurrentProcessElevated() {
			var orig string
			orig, windowsSDDL = windowsSDDL, ""
			return func() { windowsSDDL = orig }
		}
		return func() {}
	}
}

// TestExpectedWindowsTypes is a copy of TestBasics specialized for Windows with
// type assertions about the types of listeners and conns we expect.
func TestExpectedWindowsTypes(t *testing.T) {
	t.Cleanup(downgradeSDDL())
	const sock = `\\.\pipe\tailscale-test`
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprintf("%T", ln), "*safesocket.winIOPipeListener"; got != want {
		t.Errorf("got listener type %q; want %q", got, want)
	}

	errs := make(chan error, 2)

	go func() {
		s, err := ln.Accept()
		if err != nil {
			errs <- err
			return
		}
		ln.Close()

		wcc, ok := s.(*WindowsClientConn)
		if !ok {
			s.Close()
			errs <- fmt.Errorf("accepted type %T; want WindowsClientConn", s)
			return
		}
		if wcc.winioPipeConn.Fd() == 0 {
			t.Error("accepted conn had unexpected zero fd")
		}
		if wcc.token == 0 {
			t.Error("accepted conn had unexpected zero token")
		}

		s.Write([]byte("hello"))

		b := make([]byte, 1024)
		n, err := s.Read(b)
		if err != nil {
			errs <- err
			return
		}
		t.Logf("server read %d bytes.", n)
		if string(b[:n]) != "world" {
			errs <- fmt.Errorf("got %#v, expected %#v\n", string(b[:n]), "world")
			return
		}
		s.Close()
		errs <- nil
	}()

	go func() {
		c, err := Connect(sock)
		if err != nil {
			errs <- err
			return
		}
		c.Write([]byte("world"))
		b := make([]byte, 1024)
		n, err := c.Read(b)
		if err != nil {
			errs <- err
			return
		}
		if string(b[:n]) != "hello" {
			errs <- fmt.Errorf("got %#v, expected %#v\n", string(b[:n]), "hello")
		}
		c.Close()
		errs <- nil
	}()

	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}
